//! RFC-ILP-2026: MCP Proxy Relay & Binary I-PDU Tunnel
//!
//! Este módulo implementa un túnel proxy MCP de extremo a extremo:
//! - Del lado Cliente (`Client Ingress`): intercepta tramas JSON-RPC, las audita con `CognitiveFirewall`,
//!   las empaqueta en `IpduPacket` binarios y las transmite por `IlpStream::send_packet`.
//! - Del lado Servidor (`Server Egress/Gateway`): recibe las tramas `IpduPacket` binarias con
//!   `IlpStream::recv_packet`, extrae la solicitud JSON-RPC con `McpBridge::unwrap_packet`,
//!   invoca el servidor de herramientas y devuelve la respuesta encapsulada como `IpduPacket`.

#[cfg(feature = "mcp")]
use super::mcp_adapter::{
    McpBridge, McpBridgeError, McpRpcRequest, McpRpcResponse, McpSessionCorrelationTable,
};
#[cfg(feature = "mcp")]
use crate::governance::firewall::{CognitiveFirewall, FilterDecision};
#[cfg(feature = "mcp")]
use crate::governance::taint::ProcessTaintContext;
#[cfg(feature = "mcp")]
use crate::ipdu::packet::IpduPacket;
#[cfg(feature = "mcp")]
use crate::transport::IlpStream;
#[cfg(feature = "mcp")]
use std::io::{Read, Write};

#[cfg(feature = "mcp")]
/// Resultado de la intercepción de una petición MCP en el ingress del cliente.
#[derive(Debug, Clone)]
pub enum ClientIngressResult {
    /// Petición aprobada por el firewall y transmitida como trama binaria I-PDU por la red.
    Forwarded {
        packet: IpduPacket,
        decision: FilterDecision,
    },
    /// Petición bloqueada preventivamente en el borde (nunca enviada al socket remoto).
    Blocked {
        error_response: serde_json::Value,
        decision: FilterDecision,
    },
}

#[cfg(feature = "mcp")]
/// Relay de intermediación del lado cliente para llamadas MCP.
pub struct McpProxyRelay;

#[cfg(feature = "mcp")]
impl McpProxyRelay {
    /// Procesa una solicitud JSON-RPC de un cliente MCP, evalúa la política con `CognitiveFirewall`
    /// y, de ser admitida, la transmite 100% como paquete binario `IpduPacket` a través de `IlpStream`.
    pub fn handle_client_request<S: Read + Write>(
        raw_jsonrpc: &str,
        ilp_stream: &mut IlpStream<S>,
        firewall: &mut CognitiveFirewall,
        taint_context: &ProcessTaintContext,
        correlation: &McpSessionCorrelationTable,
        budget_cap: u32,
        deadline_ttl_ms: u32,
    ) -> Result<ClientIngressResult, McpBridgeError> {
        let req: McpRpcRequest = serde_json::from_str(raw_jsonrpc)
            .map_err(|e| McpBridgeError::InvalidJsonRpc(format!("Parse error: {}", e)))?;

        let session_uuid = correlation.get_or_create_session(&req.id);
        let packet = McpBridge::encapsulate_request_with_session(
            &req,
            session_uuid,
            budget_cap,
            deadline_ttl_ms,
        )?;

        let decision = firewall.inspect_egress(taint_context, &packet);

        if decision.is_allowed() {
            ilp_stream.send_packet(&packet)?;
            Ok(ClientIngressResult::Forwarded { packet, decision })
        } else {
            let err_code = decision.error_code.map(|c| c.as_i32()).unwrap_or(-32000);
            let err_resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "error": {
                    "code": err_code,
                    "message": format!("Blocked by Capa 8 MSAC Firewall: {:?}", decision.error_code),
                    "verdict": "Drop",
                    "reason": decision.reason,
                }
            });
            Ok(ClientIngressResult::Blocked {
                error_response: err_resp,
                decision,
            })
        }
    }
}

#[cfg(feature = "mcp")]
/// Gateway de recepción y despacho de tramas I-PDU hacia servidores de herramientas MCP.
pub struct IlpMcpGateway;

#[cfg(feature = "mcp")]
impl IlpMcpGateway {
    /// Recibe un paquete binario `IpduPacket` desde la red y extrae la llamada JSON-RPC original.
    pub fn receive_and_unwrap<S: Read + Write>(
        ilp_stream: &mut IlpStream<S>,
    ) -> Result<(IpduPacket, McpRpcRequest), McpBridgeError> {
        let packet = ilp_stream.recv_packet()?;
        let req = McpBridge::unwrap_packet(&packet)?;
        Ok((packet, req))
    }

    /// Encapsula una respuesta MCP JSON-RPC dentro de un `IpduPacket` binario y la transmite por `IlpStream`.
    pub fn wrap_and_send_response<S: Read + Write>(
        resp: &McpRpcResponse,
        skill_hash: u64,
        budget_spent: u32,
        ilp_stream: &mut IlpStream<S>,
    ) -> Result<IpduPacket, McpBridgeError> {
        let packet = McpBridge::encapsulate_response(resp, skill_hash, budget_spent)?;
        ilp_stream.send_packet(&packet)?;
        Ok(packet)
    }
}
