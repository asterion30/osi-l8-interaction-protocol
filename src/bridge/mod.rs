//! RFC-ILP-2026: Interoperability Bridge Module
//!
//! Proporciona adaptadores de traducción e interoperabilidad entre el protocolo binario ILP
//! de Capa 8 y estándares de la industria como Model Context Protocol (MCP) y A2A.

pub mod mcp_adapter;
pub mod proxy;

pub use mcp_adapter::{fnv1a_64, McpBridge, McpBridgeError};

#[cfg(feature = "mcp")]
pub use mcp_adapter::{McpRpcRequest, McpRpcResponse, McpSessionCorrelationTable};
#[cfg(feature = "mcp")]
pub use proxy::{
    read_bounded_line_with_deadline, ClientIngressResult, ConnectionPermit, GatewayConfig,
    IlpMcpGateway, McpGatewayServer, McpProxyRelay, McpSidecarServer, ProxyError, SidecarConfig,
};
