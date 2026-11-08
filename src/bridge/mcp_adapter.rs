//! RFC-ILP-2026: Model Context Protocol (MCP / JSON-RPC) Bridge Adapter
//!
//! Este módulo permite la interoperabilidad transparente entre el protocolo binario de
//! Capa 8 (`ilp-core`) y el estándar de la industria **Model Context Protocol (MCP)** de Anthropic,
//! encapsulando tramas JSON-RPC dentro de paquetes binarios `IpduPacket` protegidos por el MSAC.

use crate::ipdu::header::IpduError;
use core::fmt;

#[cfg(feature = "mcp")]
use crate::governance::firewall::{CognitiveFirewall, FilterDecision};
#[cfg(feature = "mcp")]
use crate::governance::taint::ProcessTaintContext;
#[cfg(feature = "mcp")]
use crate::ipdu::flags::CognitivePolicyFlags;
#[cfg(feature = "mcp")]
use crate::ipdu::header::IpduHeader;
#[cfg(feature = "mcp")]
use crate::ipdu::packet::IpduPacket;
#[cfg(feature = "mcp")]
use crate::ipdu::performatives::Performative;
#[cfg(feature = "mcp")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "mcp")]
use std::collections::HashMap;
#[cfg(feature = "mcp")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "mcp")]
use std::sync::{Arc, Mutex};

/// Constante FNV-1a 64-bit Offset Basis.
const FNV_OFFSET_BASIS_64: u64 = 0xcbf29ce484222325;
/// Constante FNV-1a 64-bit Prime.
const FNV_PRIME_64: u64 = 0x100000001b3;

/// Calcula el hash FNV-1a de 64 bits de forma determinista y sin asignación en memoria heap.
///
/// **Nota de seguridad:** FNV-1a se utiliza estrictamente para derivar `skill_namespace_hash`
/// como identificador de enrutamiento y despacho rápido en $O(1)$ sin asignación en el heap.
/// NO es una función criptográfica ni sustituye las firmas de usuario (`user_rule_sig_hash`).
#[inline]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS_64;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    hash
}

/// Errores específicos del adaptador puente MCP (JSON-RPC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpBridgeError {
    /// Método JSON-RPC no soportado por el puente MCP.
    UnsupportedMethod(String),
    /// Error en la estructura o serialización JSON-RPC.
    InvalidJsonRpc(String),
    /// Error a nivel del protocolo binario I-PDU.
    Protocol(IpduError),
}

impl From<IpduError> for McpBridgeError {
    fn from(err: IpduError) -> Self {
        Self::Protocol(err)
    }
}

impl fmt::Display for McpBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMethod(m) => write!(f, "Método MCP no soportado: {}", m),
            Self::InvalidJsonRpc(msg) => write!(f, "JSON-RPC inválido: {}", msg),
            Self::Protocol(e) => write!(f, "Error de protocolo I-PDU: {}", e),
        }
    }
}

impl std::error::Error for McpBridgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "mcp")]
/// Estructura estándar de una llamada RPC del Model Context Protocol (JSON-RPC 2.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[cfg(feature = "mcp")]
/// Estructura estándar de respuesta RPC del Model Context Protocol (JSON-RPC 2.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

#[cfg(feature = "mcp")]
impl McpRpcRequest {
    /// Construye una nueva solicitud JSON-RPC para MCP.
    pub fn new_tool_call(
        id: impl Into<serde_json::Value>,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.into(),
            method: "tools/call".to_string(),
            params: serde_json::json!({
                "name": tool_name,
                "arguments": arguments,
            }),
        }
    }

    /// Retorna el nombre de la herramienta si la solicitud es de tipo `tools/call`.
    pub fn tool_name(&self) -> Option<&str> {
        if self.method == "tools/call" {
            self.params.get("name").and_then(|v| v.as_str())
        } else {
            None
        }
    }
}

#[cfg(feature = "mcp")]
/// Tabla de correlación de sesiones en memoria para asociar `jsonrpc_id` a `session_uuid`.
///
/// **Nota de arquitectura:** `skill_namespace_hash` se deriva mediante FNV-1a para enrutamiento
/// no criptográfico en $O(1)$, mientras que `session_uuid` se administra de manera unívoca
/// y monotónica en esta tabla por conexión activa para vincular pares petición-respuesta.
#[derive(Debug, Clone, Default)]
pub struct McpSessionCorrelationTable {
    sessions: Arc<Mutex<HashMap<String, u64>>>,
    next_uuid: Arc<AtomicU64>,
}

#[cfg(feature = "mcp")]
impl McpSessionCorrelationTable {
    /// Crea una nueva tabla de correlación de sesiones.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_uuid: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Registra o recupera el `session_uuid` asociado al identificador JSON-RPC.
    pub fn get_or_create_session(&self, jsonrpc_id: &serde_json::Value) -> u64 {
        let key = match jsonrpc_id {
            serde_json::Value::String(s) => s.clone(),
            _ => jsonrpc_id.to_string(),
        };
        let mut map = self.sessions.lock().unwrap();
        *map.entry(key)
            .or_insert_with(|| self.next_uuid.fetch_add(1, Ordering::SeqCst))
    }

    /// Valida y retira el `session_uuid` para una respuesta entrante con dicho `jsonrpc_id`.
    pub fn resolve_session(&self, jsonrpc_id: &serde_json::Value) -> Option<u64> {
        let key = match jsonrpc_id {
            serde_json::Value::String(s) => s.clone(),
            _ => jsonrpc_id.to_string(),
        };
        let mut map = self.sessions.lock().unwrap();
        map.remove(&key)
    }
}

/// Adaptador puente (Bridge) para traducción bidireccional entre MCP JSON-RPC e I-PDU de Capa 8.
pub struct McpBridge;

impl McpBridge {
    /// Deriva el `skill_namespace_hash` determinista a partir del método o nombre de herramienta.
    pub fn derive_skill_hash(method: &str, tool_name: Option<&str>) -> u64 {
        if let Some(tool) = tool_name {
            let combined = format!("tools/call:{}", tool);
            fnv1a_64(combined.as_bytes())
        } else {
            fnv1a_64(method.as_bytes())
        }
    }

    #[cfg(feature = "mcp")]
    /// Deriva determinísticamente el `session_uuid` a partir del identificador `id` de JSON-RPC.
    pub fn derive_session_uuid(id: &serde_json::Value) -> u64 {
        match id {
            serde_json::Value::String(s) => fnv1a_64(s.as_bytes()),
            serde_json::Value::Number(n) => fnv1a_64(n.to_string().as_bytes()),
            _ => fnv1a_64(id.to_string().as_bytes()),
        }
    }

    #[cfg(feature = "mcp")]
    /// Encapsula una petición MCP JSON-RPC con un `session_uuid` explícito (procedente de tabla de correlación).
    pub fn encapsulate_request_with_session(
        req: &McpRpcRequest,
        session_uuid: u64,
        budget_cap: u32,
        deadline_ttl_ms: u32,
    ) -> Result<IpduPacket, McpBridgeError> {
        let performative = match req.method.as_str() {
            "tools/call" => Performative::ProposeIntent,
            "tools/list" | "prompts/list" | "resources/list" => Performative::DiscoverSkill,
            _ => return Err(McpBridgeError::UnsupportedMethod(req.method.clone())),
        };

        let tool_name = req.tool_name();
        let skill_hash = Self::derive_skill_hash(&req.method, tool_name);

        let header = IpduHeader::new(
            performative,
            1, // Tier 1: Ejecución de herramienta estándar
            CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE,
            skill_hash,
            session_uuid,
            budget_cap,
            deadline_ttl_ms,
            0,
        )?;

        let payload_bytes = serde_json::to_vec(req).map_err(|e| {
            McpBridgeError::InvalidJsonRpc(format!("Error de serialización JSON-RPC: {}", e))
        })?;

        Ok(IpduPacket::try_new(header, payload_bytes)?)
    }

    #[cfg(feature = "mcp")]
    /// Encapsula una petición MCP JSON-RPC dentro de un paquete canónico `IpduPacket`.
    pub fn encapsulate_request(
        req: &McpRpcRequest,
        budget_cap: u32,
        deadline_ttl_ms: u32,
    ) -> Result<IpduPacket, McpBridgeError> {
        let session_uuid = Self::derive_session_uuid(&req.id);
        Self::encapsulate_request_with_session(req, session_uuid, budget_cap, deadline_ttl_ms)
    }

    #[cfg(feature = "mcp")]
    /// Desencapsula una petición MCP JSON-RPC desde un paquete `IpduPacket`.
    pub fn decapsulate_request(packet: &IpduPacket) -> Result<McpRpcRequest, McpBridgeError> {
        let req: McpRpcRequest = serde_json::from_slice(packet.payload()).map_err(|e| {
            McpBridgeError::InvalidJsonRpc(format!("Error al deserializar JSON-RPC: {}", e))
        })?;
        Ok(req)
    }

    #[cfg(feature = "mcp")]
    /// Desencapsula una petición MCP JSON-RPC desde un paquete `IpduPacket` (alias funcional de decapsulate_request).
    #[inline]
    pub fn unwrap_packet(packet: &IpduPacket) -> Result<McpRpcRequest, McpBridgeError> {
        Self::decapsulate_request(packet)
    }

    #[cfg(feature = "mcp")]
    /// Encapsula una respuesta MCP JSON-RPC dentro de un paquete `IpduPacket`.
    ///
    /// Mapeo de campos:
    /// - `result != null` -> `Performative::AttestResult`
    /// - `error != null` -> `Performative::RejectPolicy`
    /// - ningún campo -> `Err(McpBridgeError::InvalidJsonRpc)`
    pub fn encapsulate_response(
        resp: &McpRpcResponse,
        skill_hash: u64,
        budget_spent: u32,
    ) -> Result<IpduPacket, McpBridgeError> {
        let performative = if resp.error.is_some() {
            Performative::RejectPolicy
        } else if resp.result.is_some() {
            Performative::AttestResult
        } else {
            return Err(McpBridgeError::InvalidJsonRpc(
                "La respuesta JSON-RPC debe contener 'result' o 'error'".to_string(),
            ));
        };

        let session_uuid = Self::derive_session_uuid(&resp.id);
        let header = IpduHeader::new(
            performative,
            1,
            CognitivePolicyFlags::EMPTY,
            skill_hash,
            session_uuid,
            budget_spent,
            5_000,
            0,
        )?;

        let payload_bytes = serde_json::to_vec(resp).map_err(|e| {
            McpBridgeError::InvalidJsonRpc(format!("Error de serialización JSON-RPC: {}", e))
        })?;

        Ok(IpduPacket::try_new(header, payload_bytes)?)
    }

    #[cfg(feature = "mcp")]
    /// Desencapsula una respuesta MCP JSON-RPC desde un paquete `IpduPacket`.
    pub fn decapsulate_response(packet: &IpduPacket) -> Result<McpRpcResponse, McpBridgeError> {
        let resp: McpRpcResponse = serde_json::from_slice(packet.payload()).map_err(|e| {
            McpBridgeError::InvalidJsonRpc(format!(
                "Error al deserializar respuesta JSON-RPC: {}",
                e
            ))
        })?;
        Ok(resp)
    }

    #[cfg(feature = "mcp")]
    /// Encapsula la petición MCP e invoca la auditoría obligatoria en el Firewall Cognitivo (MSAC).
    /// Si el firewall emite `Drop`, el llamador recibe el paquete con la decisión forense sin salir a la red.
    pub fn inspect_and_wrap(
        firewall: &mut CognitiveFirewall,
        taint_context: &ProcessTaintContext,
        req: &McpRpcRequest,
        budget_cap: u32,
        deadline_ttl_ms: u32,
    ) -> Result<(IpduPacket, FilterDecision), McpBridgeError> {
        let packet = Self::encapsulate_request(req, budget_cap, deadline_ttl_ms)?;
        let decision = firewall.inspect_egress(taint_context, &packet);
        Ok((packet, decision))
    }
}
