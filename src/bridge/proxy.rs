//! RFC-ILP-2026: MCP Proxy Relay, Gateway & Production Sidecar Server
//!
//! Este módulo implementa el servidor sidecar MCP y gateway de Capa 8:
//! - **Evaluate-Before-Connect**: El firewall cognitivo evalúa en memoria las peticiones
//!   JSON-RPC; si el veredicto es `Drop`, jamás se abre un socket TCP ni se emiten paquetes SYN al gateway.
//! - **Aislamiento y Correlación**: Asociación `(client_conn_id, request_id)` con expiración por TTL y consumo estricto.
//! - **Límites Operativos**: Lectura bounded con `read_bounded_line_with_deadline` para mitigar Slowloris y OOM,
//!   reserva atómica de conexiones con `ConnectionPermit` (CAS), y timeouts I/O.
//! - **Autenticación PSK**: Firma y verificación criptográfica de tramas con SipHash-2-4 MAC.
//! - **Taint Ingress Dinámico**: Auto-manchado de procesos ante respuestas sensibles de herramientas.

#[cfg(feature = "mcp")]
use super::mcp_adapter::{
    McpBridge, McpBridgeError, McpRpcRequest, McpRpcResponse, McpSessionCorrelationTable,
};
#[cfg(feature = "mcp")]
use crate::governance::firewall::{CognitiveFirewall, FilterDecision};
#[cfg(feature = "mcp")]
use crate::governance::gatekeeper::HeuristicGatekeeper;
#[cfg(feature = "mcp")]
use crate::governance::taint::{ProcessTaintContext, TaintTag};
#[cfg(feature = "mcp")]
use crate::ipdu::auth::{compute_frame_mac, verify_frame_mac};
#[cfg(feature = "mcp")]
use crate::ipdu::packet::IpduPacket;
#[cfg(feature = "mcp")]
use crate::transport::IlpStream;
#[cfg(feature = "mcp")]
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(feature = "mcp")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "mcp")]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[cfg(feature = "mcp")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "mcp")]
use std::thread;
#[cfg(feature = "mcp")]
use std::time::{Duration, Instant};

#[cfg(feature = "mcp")]
static NEXT_CLIENT_CONN_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "mcp")]
/// Errores operativos del proxy y servidores de Capa 8.
#[derive(Debug)]
pub enum ProxyError {
    Io(std::io::Error),
    PayloadTooLarge,
    RequestDeadlineExceeded,
    McpBridge(McpBridgeError),
    AuthFailed(String),
}

#[cfg(feature = "mcp")]
impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Error I/O en proxy: {}", e),
            Self::PayloadTooLarge => {
                write!(f, "Payload size exceeds maximum allowed limit (64 KiB)")
            }
            Self::RequestDeadlineExceeded => {
                write!(f, "Request deadline exceeded (Slowloris timeout)")
            }
            Self::McpBridge(e) => write!(f, "Error en adaptador MCP: {}", e),
            Self::AuthFailed(msg) => write!(f, "Fallo de autenticación: {}", msg),
        }
    }
}

#[cfg(feature = "mcp")]
impl std::error::Error for ProxyError {}

#[cfg(feature = "mcp")]
impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(feature = "mcp")]
impl From<McpBridgeError> for ProxyError {
    fn from(e: McpBridgeError) -> Self {
        Self::McpBridge(e)
    }
}

#[cfg(feature = "mcp")]
/// Configuración operativa para los servidores Sidecar y Gateway MCP.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Longitud máxima permitida para una línea JSON-RPC entrante (bytes). Default: 65.536.
    pub max_line_bytes: usize,
    /// Conexiones TCP concurrentes máximas permitidas. Default: 32.
    pub max_concurrent_connections: usize,
    /// Tiempo límite para operaciones de lectura/escritura en sockets. Default: 5.000 ms.
    pub io_timeout: Duration,
    /// Tiempo de vida máximo para entradas pendientes en la tabla de correlación. Default: 30.000 ms.
    pub session_ttl: Duration,
    /// Presupuesto por defecto para tramas de negociación. Default: 10.000.
    pub budget_cap: u32,
    /// Plazo límite TTL en milisegundos para tramas I-PDU. Default: 5.000 ms.
    pub deadline_ttl_ms: u32,
    /// Clave pre-compartida (PSK) opcional de 128 bits para autenticación MAC de tramas.
    pub psk: Option<[u8; 16]>,
}

#[cfg(feature = "mcp")]
impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            max_line_bytes: 65_536,
            max_concurrent_connections: 32,
            io_timeout: Duration::from_millis(5_000),
            session_ttl: Duration::from_millis(30_000),
            budget_cap: 10_000,
            deadline_ttl_ms: 5_000,
            psk: None,
        }
    }
}

#[cfg(feature = "mcp")]
/// Alias simétrico de configuración para el Gateway.
pub type GatewayConfig = SidecarConfig;

#[cfg(feature = "mcp")]
/// Permiso RAII de reserva atómica de conexiones concurrentes sin condiciones de carrera.
#[derive(Debug)]
pub struct ConnectionPermit {
    counter: Arc<AtomicUsize>,
}

#[cfg(feature = "mcp")]
impl ConnectionPermit {
    /// Intenta adquirir atómicamente un permiso de conexión mediante CAS (Compare-And-Swap).
    pub fn try_acquire(counter: Arc<AtomicUsize>, max: usize) -> Option<Self> {
        let res = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |curr| {
            if curr < max {
                Some(curr + 1)
            } else {
                None
            }
        });
        res.ok().map(|_| Self { counter })
    }
}

#[cfg(feature = "mcp")]
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Release);
    }
}

#[cfg(feature = "mcp")]
/// Lee una línea completa delimitada por `\n` acotando la memoria a `max_bytes`
/// e imponiendo un plazo máximo acumulado (`total_deadline`) para mitigar ataques Slowloris.
pub fn read_bounded_line_with_deadline(
    stream: &TcpStream,
    reader: &mut impl BufRead,
    max_bytes: usize,
    total_deadline: Duration,
) -> Result<String, ProxyError> {
    let start = Instant::now();
    let mut line = String::new();

    loop {
        let elapsed = start.elapsed();
        let remaining = total_deadline
            .checked_sub(elapsed)
            .ok_or(ProxyError::RequestDeadlineExceeded)?;

        let timeout_to_set = remaining.max(Duration::from_millis(1));
        let _ = stream.set_read_timeout(Some(timeout_to_set));

        let mut chunk = String::new();
        let take_limit = (max_bytes + 1).saturating_sub(line.len()) as u64;
        let mut take_reader = reader.take(take_limit);

        match take_reader.read_line(&mut chunk) {
            Ok(0) => {
                if line.is_empty() {
                    return Ok(String::new());
                }
                break;
            }
            Ok(_) => {
                line.push_str(&chunk);
                if line.len() > max_bytes {
                    return Err(ProxyError::PayloadTooLarge);
                }
                if line.ends_with('\n') {
                    break;
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                if start.elapsed() >= total_deadline {
                    return Err(ProxyError::RequestDeadlineExceeded);
                }
                continue;
            }
            Err(e) => return Err(ProxyError::Io(e)),
        }

        if start.elapsed() >= total_deadline {
            return Err(ProxyError::RequestDeadlineExceeded);
        }
    }

    Ok(line)
}

#[cfg(feature = "mcp")]
/// Resultado de la intercepción de una petición MCP en el ingress del cliente.
#[derive(Debug, Clone)]
pub enum ClientIngressResult {
    /// Petición aprobada por el firewall y autorizada a conectarse al gateway.
    Forwarded {
        packet: IpduPacket,
        decision: FilterDecision,
    },
    /// Petición bloqueada preventivamente en memoria (cero conexiones de red abiertas).
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
    /// Evalúa en memoria una solicitud JSON-RPC contra el Firewall Cognitivo (MSAC)
    /// **antes** de abrir cualquier socket o conexión de red hacia el gateway.
    ///
    /// Invariante Zero-Connect: Si la decisión es `Drop`, ningún recurso de red es consumido.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_client_request(
        raw_jsonrpc: &str,
        firewall: &mut CognitiveFirewall,
        taint_context: &ProcessTaintContext,
        correlation: &McpSessionCorrelationTable,
        client_conn_id: u64,
        budget_cap: u32,
        deadline_ttl_ms: u32,
        session_ttl: Duration,
    ) -> Result<ClientIngressResult, McpBridgeError> {
        let req: McpRpcRequest = serde_json::from_str(raw_jsonrpc)
            .map_err(|e| McpBridgeError::InvalidJsonRpc(format!("Parse error: {}", e)))?;

        let session_uuid = correlation.register_session(client_conn_id, &req.id, session_ttl)?;
        let packet = McpBridge::encapsulate_request_with_session(
            &req,
            session_uuid,
            budget_cap,
            deadline_ttl_ms,
        )?;

        let decision = firewall.inspect_egress(taint_context, &packet);

        if decision.is_allowed() {
            Ok(ClientIngressResult::Forwarded { packet, decision })
        } else {
            // Limpiar la sesión correlacionada para evitar fugas de memoria por peticiones bloqueadas
            let _ = correlation.resolve_session(client_conn_id, &req.id, session_uuid);

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

    /// Encapsula una respuesta MCP JSON-RPC dentro de un `IpduPacket` binario con el `session_uuid` recibido.
    pub fn wrap_and_send_response<S: Read + Write>(
        resp: &McpRpcResponse,
        skill_hash: u64,
        session_uuid: u64,
        budget_spent: u32,
        ilp_stream: &mut IlpStream<S>,
    ) -> Result<IpduPacket, McpBridgeError> {
        let packet = McpBridge::encapsulate_response(resp, skill_hash, session_uuid, budget_spent)?;
        ilp_stream.send_packet(&packet)?;
        Ok(packet)
    }
}

#[cfg(feature = "mcp")]
/// Servidor Sidecar MCP de producción en espacio de usuario.
///
/// Expone un listener TCP para clientes MCP, evalúa la política MSAC en memoria (Zero-Connect)
/// y transmite tramas binarias I-PDU hacia el Gateway remoto únicamente cuando la petición es autorizada.
pub struct McpSidecarServer {
    pub addr: String,
    pub active_connections: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

#[cfg(feature = "mcp")]
impl McpSidecarServer {
    /// Inicia el servidor sidecar en un hilo de fondo.
    pub fn start(
        listen_addr: &str,
        gateway_addr: String,
        firewall: CognitiveFirewall,
        taint_context: Arc<Mutex<ProcessTaintContext>>,
        config: SidecarConfig,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(listen_addr)?;
        let addr = listener.local_addr()?.to_string();
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let correlation = Arc::new(McpSessionCorrelationTable::new());

        let shut_clone = Arc::clone(&shutdown);
        let active_clone = Arc::clone(&active_connections);

        thread::spawn(move || {
            while !shut_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client_stream, _)) => {
                        let Some(permit) = ConnectionPermit::try_acquire(
                            Arc::clone(&active_clone),
                            config.max_concurrent_connections,
                        ) else {
                            drop(client_stream);
                            continue;
                        };

                        let gateway_target = gateway_addr.clone();
                        let taint_ref = Arc::clone(&taint_context);
                        let mut firewall_clone = firewall.clone();
                        let corr_ref = Arc::clone(&correlation);
                        let cfg = config.clone();

                        thread::spawn(move || {
                            let _permit = permit;
                            let _ = client_stream.set_read_timeout(Some(cfg.io_timeout));
                            let _ = client_stream.set_write_timeout(Some(cfg.io_timeout));

                            let client_conn_id = NEXT_CLIENT_CONN_ID.fetch_add(1, Ordering::SeqCst);
                            let Ok(reader_stream) = client_stream.try_clone() else {
                                return;
                            };
                            let mut client_reader = BufReader::new(reader_stream);
                            let mut client_writer = client_stream;

                            loop {
                                let line = match read_bounded_line_with_deadline(
                                    &client_writer,
                                    &mut client_reader,
                                    cfg.max_line_bytes,
                                    cfg.io_timeout,
                                ) {
                                    Ok(l) => {
                                        if l.is_empty() {
                                            break;
                                        }
                                        l
                                    }
                                    Err(ProxyError::PayloadTooLarge) => {
                                        let err_resp = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": null,
                                            "error": {
                                                "code": -32600,
                                                "message": "Payload size exceeds maximum allowed limit (64 KiB)"
                                            }
                                        });
                                        let mut err_str = err_resp.to_string();
                                        err_str.push('\n');
                                        let _ = client_writer.write_all(err_str.as_bytes());
                                        let _ = client_writer.flush();
                                        break;
                                    }
                                    Err(ProxyError::RequestDeadlineExceeded) => {
                                        let err_resp = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": null,
                                            "error": {
                                                "code": -32000,
                                                "message": "Request deadline exceeded"
                                            }
                                        });
                                        let mut err_str = err_resp.to_string();
                                        err_str.push('\n');
                                        let _ = client_writer.write_all(err_str.as_bytes());
                                        let _ = client_writer.flush();
                                        break;
                                    }
                                    Err(_) => break,
                                };

                                // Inspección de claims de tinte explícitos en los parámetros de la solicitud
                                if let Ok(req_val) =
                                    serde_json::from_str::<serde_json::Value>(&line)
                                {
                                    if let Some(claim) = req_val
                                        .get("params")
                                        .and_then(|p| p.get("_ilp_taint_claim"))
                                        .and_then(|c| c.as_str())
                                    {
                                        if let Some(tag) = TaintTag::from_name(claim) {
                                            taint_ref
                                                .lock()
                                                .unwrap()
                                                .apply_taint(tag, "mcp:client:taint_claim");
                                        }
                                    }
                                }

                                let current_taint = taint_ref.lock().unwrap().clone();
                                match McpProxyRelay::evaluate_client_request(
                                    &line,
                                    &mut firewall_clone,
                                    &current_taint,
                                    &corr_ref,
                                    client_conn_id,
                                    cfg.budget_cap,
                                    cfg.deadline_ttl_ms,
                                    cfg.session_ttl,
                                ) {
                                    Ok(ClientIngressResult::Forwarded { mut packet, .. }) => {
                                        // Firma de trama con PSK si está configurada
                                        if let Some(ref key) = cfg.psk {
                                            let mac = compute_frame_mac(
                                                packet.header(),
                                                packet.payload(),
                                                key,
                                            );
                                            packet.set_user_rule_sig_hash(mac);
                                        }

                                        // Zero-Connect: Conexión abierta ÚNICAMENTE tras aprobación formal
                                        match TcpStream::connect(&gateway_target) {
                                            Ok(gateway_tcp) => {
                                                let _ = gateway_tcp
                                                    .set_read_timeout(Some(cfg.io_timeout));
                                                let _ = gateway_tcp
                                                    .set_write_timeout(Some(cfg.io_timeout));

                                                let mut ilp_stream = IlpStream::new(gateway_tcp);
                                                if ilp_stream.send_packet(&packet).is_ok() {
                                                    if let Ok(resp_packet) =
                                                        ilp_stream.recv_packet()
                                                    {
                                                        // Verificación de MAC en la respuesta si PSK está activa
                                                        if let Some(ref key) = cfg.psk {
                                                            if !verify_frame_mac(
                                                                resp_packet.header(),
                                                                resp_packet.payload(),
                                                                key,
                                                                resp_packet
                                                                    .header()
                                                                    .user_rule_sig_hash,
                                                            ) {
                                                                let err_resp = serde_json::json!({
                                                                    "jsonrpc": "2.0",
                                                                    "id": null,
                                                                    "error": {
                                                                        "code": -32001,
                                                                        "message": "ILP Sidecar: Gateway response frame MAC verification failed"
                                                                    }
                                                                });
                                                                let mut err_str =
                                                                    err_resp.to_string();
                                                                err_str.push('\n');
                                                                let _ = client_writer
                                                                    .write_all(err_str.as_bytes());
                                                                let _ = client_writer.flush();
                                                                break;
                                                            }
                                                        }

                                                        // Taint Ingress Tracking: Detección dinámica de datos sensibles en la respuesta
                                                        let detected_tags =
                                                            HeuristicGatekeeper::detect_sensitive_classes(
                                                                resp_packet.payload(),
                                                            );
                                                        for tag in detected_tags {
                                                            taint_ref.lock().unwrap().apply_taint(
                                                                tag,
                                                                "mcp:ingress:tool_response",
                                                            );
                                                        }

                                                        if let Ok(resp) =
                                                            McpBridge::decapsulate_response(
                                                                &resp_packet,
                                                            )
                                                        {
                                                            // Consumo y verificación estricta de session_uuid y expiración
                                                            match corr_ref.resolve_session(
                                                                client_conn_id,
                                                                &resp.id,
                                                                resp_packet.header().session_uuid,
                                                            ) {
                                                                Ok(_) => {
                                                                    if let Ok(mut resp_str) =
                                                                        serde_json::to_string(&resp)
                                                                    {
                                                                        resp_str.push('\n');
                                                                        let _ = client_writer
                                                                            .write_all(
                                                                                resp_str.as_bytes(),
                                                                            );
                                                                        let _ =
                                                                            client_writer.flush();
                                                                    }
                                                                }
                                                                Err(
                                                                    McpBridgeError::SessionExpired,
                                                                ) => {
                                                                    let err_resp = serde_json::json!({
                                                                        "jsonrpc": "2.0",
                                                                        "id": resp.id,
                                                                        "error": {
                                                                            "code": -32000,
                                                                            "message": "ILP Session expired (TTL exceeded)"
                                                                        }
                                                                    });
                                                                    let mut err_str =
                                                                        err_resp.to_string();
                                                                    err_str.push('\n');
                                                                    let _ = client_writer
                                                                        .write_all(
                                                                            err_str.as_bytes(),
                                                                        );
                                                                    let _ = client_writer.flush();
                                                                }
                                                                Err(e) => {
                                                                    let err_resp = serde_json::json!({
                                                                        "jsonrpc": "2.0",
                                                                        "id": resp.id,
                                                                        "error": {
                                                                            "code": -32000,
                                                                            "message": format!("ILP Session resolution error: {}", e)
                                                                        }
                                                                    });
                                                                    let mut err_str =
                                                                        err_resp.to_string();
                                                                    err_str.push('\n');
                                                                    let _ = client_writer
                                                                        .write_all(
                                                                            err_str.as_bytes(),
                                                                        );
                                                                    let _ = client_writer.flush();
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let err_resp = serde_json::json!({
                                                    "jsonrpc": "2.0",
                                                    "id": null,
                                                    "error": {
                                                        "code": -32603,
                                                        "message": format!("Gateway connection failed: {}", e)
                                                    }
                                                });
                                                let mut err_str = err_resp.to_string();
                                                err_str.push('\n');
                                                let _ = client_writer.write_all(err_str.as_bytes());
                                                let _ = client_writer.flush();
                                            }
                                        }
                                    }
                                    Ok(ClientIngressResult::Blocked { error_response, .. }) => {
                                        // Bloqueo en memoria: CERO conexiones al gateway
                                        let mut err_str = error_response.to_string();
                                        err_str.push('\n');
                                        let _ = client_writer.write_all(err_str.as_bytes());
                                        let _ = client_writer.flush();
                                    }
                                    Err(McpBridgeError::DuplicateInFlightRequestId) => {
                                        let err_resp = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": null,
                                            "error": {
                                                "code": -32600,
                                                "message": "Duplicate in-flight request ID on connection"
                                            }
                                        });
                                        let mut err_str = err_resp.to_string();
                                        err_str.push('\n');
                                        let _ = client_writer.write_all(err_str.as_bytes());
                                        let _ = client_writer.flush();
                                    }
                                    Err(e) => {
                                        let err_resp = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": null,
                                            "error": {
                                                "code": -32600,
                                                "message": format!("ILP Protocol error: {}", e)
                                            }
                                        });
                                        let mut err_str = err_resp.to_string();
                                        err_str.push('\n');
                                        let _ = client_writer.write_all(err_str.as_bytes());
                                        let _ = client_writer.flush();
                                    }
                                }
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            active_connections,
            shutdown,
        })
    }
}

#[cfg(feature = "mcp")]
impl Drop for McpSidecarServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

#[cfg(feature = "mcp")]
/// Gateway servidor de Capa 8 que recibe tramas binarias I-PDU y las despacha al servidor MCP de herramientas.
pub struct McpGatewayServer {
    pub addr: String,
    pub accepted_connections: Arc<AtomicUsize>,
    pub active_connections: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

#[cfg(feature = "mcp")]
impl McpGatewayServer {
    /// Inicia el Gateway en un hilo de fondo.
    pub fn start(
        listen_addr: &str,
        tool_server_addr: String,
        config: SidecarConfig,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(listen_addr)?;
        let addr = listener.local_addr()?.to_string();
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let active_connections = Arc::new(AtomicUsize::new(0));

        let shut_clone = Arc::clone(&shutdown);
        let accepted_clone = Arc::clone(&accepted_connections);
        let active_clone = Arc::clone(&active_connections);

        thread::spawn(move || {
            while !shut_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        accepted_clone.fetch_add(1, Ordering::SeqCst);

                        let Some(permit) = ConnectionPermit::try_acquire(
                            Arc::clone(&active_clone),
                            config.max_concurrent_connections,
                        ) else {
                            drop(stream);
                            continue;
                        };

                        let backend_target = tool_server_addr.clone();
                        let cfg = config.clone();

                        thread::spawn(move || {
                            let _permit = permit;
                            let _ = stream.set_read_timeout(Some(cfg.io_timeout));
                            let _ = stream.set_write_timeout(Some(cfg.io_timeout));

                            let mut ilp_stream = IlpStream::new(stream);
                            while let Ok((packet, mcp_req)) =
                                IlpMcpGateway::receive_and_unwrap(&mut ilp_stream)
                            {
                                // Verificación de MAC en la trama recibida si PSK está configurada
                                if let Some(ref key) = cfg.psk {
                                    if !verify_frame_mac(
                                        packet.header(),
                                        packet.payload(),
                                        key,
                                        packet.header().user_rule_sig_hash,
                                    ) {
                                        let err_resp = McpRpcResponse {
                                            jsonrpc: "2.0".to_string(),
                                            id: mcp_req.id.clone(),
                                            result: None,
                                            error: Some(serde_json::json!({
                                                "code": -32001,
                                                "message": "ILP Gateway: Frame MAC authentication failed"
                                            })),
                                        };
                                        let mut resp_pkt = match McpBridge::encapsulate_response(
                                            &err_resp,
                                            packet.header().skill_namespace_hash,
                                            packet.header().session_uuid,
                                            0,
                                        ) {
                                            Ok(p) => p,
                                            Err(_) => break,
                                        };
                                        let mac = compute_frame_mac(
                                            resp_pkt.header(),
                                            resp_pkt.payload(),
                                            key,
                                        );
                                        resp_pkt.set_user_rule_sig_hash(mac);
                                        let _ = ilp_stream.send_packet(&resp_pkt);
                                        continue;
                                    }
                                }

                                // Comunicación con el servidor de herramientas de backend
                                let backend_result = (|| -> Result<McpRpcResponse, String> {
                                    let mut backend = TcpStream::connect(&backend_target)
                                        .map_err(|e| format!("Connection error: {}", e))?;
                                    let _ = backend.set_read_timeout(Some(cfg.io_timeout));
                                    let _ = backend.set_write_timeout(Some(cfg.io_timeout));

                                    let mut req_str = serde_json::to_string(&mcp_req)
                                        .map_err(|e| format!("Serialization error: {}", e))?;
                                    req_str.push('\n');
                                    backend
                                        .write_all(req_str.as_bytes())
                                        .map_err(|e| format!("Write error: {}", e))?;
                                    backend.flush().map_err(|e| format!("Flush error: {}", e))?;

                                    let mut backend_reader = BufReader::new(backend);
                                    let mut backend_resp = String::new();
                                    let mut take_reader =
                                        (&mut backend_reader).take(cfg.max_line_bytes as u64 + 1);

                                    take_reader
                                        .read_line(&mut backend_resp)
                                        .map_err(|e| format!("Read error: {}", e))?;

                                    if backend_resp.is_empty() {
                                        return Err(
                                            "Empty response from backend tool server".to_string()
                                        );
                                    }
                                    if backend_resp.len() > cfg.max_line_bytes {
                                        return Err(
                                            "Backend response exceeded max line bytes".to_string()
                                        );
                                    }

                                    serde_json::from_str::<McpRpcResponse>(&backend_resp)
                                        .map_err(|e| format!("Invalid JSON-RPC response: {}", e))
                                })();

                                let mcp_resp = match backend_result {
                                    Ok(resp) => resp,
                                    Err(err_msg) => McpRpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: mcp_req.id.clone(),
                                        result: None,
                                        error: Some(serde_json::json!({
                                            "code": -32002,
                                            "message": format!("ILP Gateway: Backend tool server unreachable or timed out: {}", err_msg)
                                        })),
                                    },
                                };

                                let mut resp_packet = match McpBridge::encapsulate_response(
                                    &mcp_resp,
                                    packet.header().skill_namespace_hash,
                                    packet.header().session_uuid,
                                    100,
                                ) {
                                    Ok(p) => p,
                                    Err(_) => break,
                                };

                                if let Some(ref key) = cfg.psk {
                                    let mac = compute_frame_mac(
                                        resp_packet.header(),
                                        resp_packet.payload(),
                                        key,
                                    );
                                    resp_packet.set_user_rule_sig_hash(mac);
                                }

                                if ilp_stream.send_packet(&resp_packet).is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            accepted_connections,
            active_connections,
            shutdown,
        })
    }
}

#[cfg(feature = "mcp")]
impl Drop for McpGatewayServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}
