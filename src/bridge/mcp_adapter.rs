//! RFC-ILP-2026: Model Context Protocol (MCP / JSON-RPC) Bridge Adapter
//!
//! Este módulo permite la interoperabilidad transparente entre el protocolo binario de
//! Capa 8 (`ilp-core`) y el estándar de la industria **Model Context Protocol (MCP)** de Anthropic,
//! encapsulando tramas JSON-RPC dentro de paquetes binarios `IpduPacket` protegidos por el MSAC.

#[cfg(feature = "mcp")]
use crate::governance::firewall::{CognitiveFirewall, FilterDecision};
#[cfg(feature = "mcp")]
use crate::governance::taint::ProcessTaintContext;
#[cfg(feature = "mcp")]
use crate::ipdu::flags::CognitivePolicyFlags;
#[cfg(feature = "mcp")]
use crate::ipdu::header::{IpduError, IpduHeader};
#[cfg(feature = "mcp")]
use crate::ipdu::packet::IpduPacket;
#[cfg(feature = "mcp")]
use crate::ipdu::performatives::Performative;
#[cfg(feature = "mcp")]
use serde::{Deserialize, Serialize};

/// Constante FNV-1a 64-bit Offset Basis.
const FNV_OFFSET_BASIS_64: u64 = 0xcbf29ce484222325;
/// Constante FNV-1a 64-bit Prime.
const FNV_PRIME_64: u64 = 0x100000001b3;

/// Calcula el hash FNV-1a de 64 bits de forma determinista y sin asignación en memoria heap.
/// Utilizado para derivar `skill_namespace_hash` a partir del nombre de herramientas o métodos MCP.
#[inline]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS_64;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    hash
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
    /// Encapsula una petición MCP JSON-RPC dentro de un paquete canónico `IpduPacket`.
    ///
    /// Mapeo de campos:
    /// - `tools/call` -> `Performative::ProposeIntent`
    /// - `tools/list` / `prompts/list` / `resources/list` -> `Performative::DiscoverSkill`
    /// - otros -> `Performative::ProposeIntent`
    /// - `skill_namespace_hash` -> FNV-1a del nombre de la herramienta
    pub fn encapsulate_request(
        req: &McpRpcRequest,
        session_uuid: u64,
        budget_cap: u32,
        deadline_ttl_ms: u32,
    ) -> Result<IpduPacket, IpduError> {
        let tool_name = req.tool_name();
        let skill_hash = Self::derive_skill_hash(&req.method, tool_name);

        let performative = match req.method.as_str() {
            "tools/list" | "prompts/list" | "resources/list" => Performative::DiscoverSkill,
            _ => Performative::ProposeIntent,
        };

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

        let payload_bytes = serde_json::to_vec(req)
            .map_err(|e| IpduError::Io(format!("Error de serialización JSON-RPC: {}", e)))?;

        Ok(IpduPacket::new(header, payload_bytes))
    }

    #[cfg(feature = "mcp")]
    /// Desencapsula una petición MCP JSON-RPC desde un paquete `IpduPacket`.
    pub fn decapsulate_request(packet: &IpduPacket) -> Result<McpRpcRequest, IpduError> {
        let req: McpRpcRequest = serde_json::from_slice(&packet.payload)
            .map_err(|e| IpduError::Io(format!("Error al deserializar JSON-RPC: {}", e)))?;
        Ok(req)
    }

    #[cfg(feature = "mcp")]
    /// Encapsula una respuesta MCP JSON-RPC dentro de un paquete de confirmación `IpduPacket`.
    pub fn encapsulate_response(
        resp: &McpRpcResponse,
        session_uuid: u64,
        skill_hash: u64,
        budget_spent: u32,
    ) -> Result<IpduPacket, IpduError> {
        let header = IpduHeader::new(
            Performative::CommitContract,
            1,
            CognitivePolicyFlags::EMPTY,
            skill_hash,
            session_uuid,
            budget_spent,
            5_000,
            0,
        )?;

        let payload_bytes = serde_json::to_vec(resp)
            .map_err(|e| IpduError::Io(format!("Error de serialización JSON-RPC: {}", e)))?;

        Ok(IpduPacket::new(header, payload_bytes))
    }

    #[cfg(feature = "mcp")]
    /// Desencapsula una respuesta MCP JSON-RPC desde un paquete `IpduPacket`.
    pub fn decapsulate_response(packet: &IpduPacket) -> Result<McpRpcResponse, IpduError> {
        let resp: McpRpcResponse = serde_json::from_slice(&packet.payload).map_err(|e| {
            IpduError::Io(format!("Error al deserializar respuesta JSON-RPC: {}", e))
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
        session_uuid: u64,
        budget_cap: u32,
        deadline_ttl_ms: u32,
    ) -> Result<(IpduPacket, FilterDecision), IpduError> {
        let packet = Self::encapsulate_request(req, session_uuid, budget_cap, deadline_ttl_ms)?;
        let decision = firewall.inspect_egress(taint_context, &packet);
        Ok((packet, decision))
    }
}
