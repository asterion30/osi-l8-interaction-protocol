//! Binario Desplegable: ILP MCP Sidecar Daemon (Capa 8 / RFC-ILP-2026)
//!
//! Intercepta tráfico Model Context Protocol (MCP) JSON-RPC, ejecuta el
//! Cognitive Reference Monitor (MSAC) en memoria (Zero-Connect) y reenvía
//! tráfico autorizado en formato binario I-PDU hacia el Gateway ILP.

#[cfg(feature = "mcp")]
use ilp_core::bridge::{McpSidecarServer, SidecarConfig};
#[cfg(feature = "mcp")]
use ilp_core::governance::{
    CognitiveFirewall, ProcessTaintContext, TaintTag, UserGovernancePolicy,
};
#[cfg(feature = "mcp")]
use std::net::SocketAddr;
#[cfg(feature = "mcp")]
use std::sync::{Arc, Mutex};

fn print_help() {
    println!(
        "Uso: ilp_mcp_sidecar [OPCIONES]\n\n\
        Opciones:\n  \
          --listen <IP:PUERTO>       Dirección de escucha para clientes MCP (default: 127.0.0.1:9001)\n  \
          --stdio                    Modo transporte stdio (stdin/stdout) para clientes MCP locales (incompatible con --listen)\n  \
          --gateway <IP:PUERTO>      Dirección del Gateway ILP remoto (default: 127.0.0.1:9002)\n  \
          --policy <RUTA>            Ruta al archivo de políticas MSAC (default: policies/default_msac.conf)\n  \
          --initial-taint <TAGS>     Etiquetas iniciales de tinte separadas por coma (ej. medical_pii,financial_data)\n  \
          --trust-client-claims      Acepta claims explícitos _ilp_taint_claim en solicitudes cliente (default: false)\n  \
          --psk-file <RUTA>          Carga clave pre-compartida de 128 bits desde archivo (requiere permisos 0600 o 0400)\n  \
          --psk <HEX_KEY>            [DEPRECATED/TEST-ONLY] Clave pre-compartida en línea de comandos (visible en /proc)\n  \
          --encrypt-payload          Habilita cifrado ChaCha20 (RFC 8439) en payload de tramas (default: activo)\n  \
          --no-encrypt-payload       Deshabilita cifrado de payload (transmite JSON-RPC en claro)\n  \
          --audit-log <RUTA>         Ruta para archivo de log forense estructurado en formato JSONL para SIEM\n  \
          --allow-non-loopback       Permite enlazar a interfaces de red externas (requiere PSK)\n  \
          --check-config             Valida sintaxis de la política y configuración, saliendo con código 0\n  \
          -h, --help                 Muestra esta ayuda y finaliza\n\n\
        Variables de entorno:\n  \
          ILP_PSK_HEX                Clave pre-compartida de 128 bits (32 dígitos hexadecimales)\n"
    );
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("Error: el binario ilp_mcp_sidecar requiere la feature 'mcp'.");
    eprintln!("Compila ejecutando: cargo build --bin ilp_mcp_sidecar --features mcp");
    std::process::exit(1);
}

#[cfg(feature = "mcp")]
use ilp_core::ipdu::{load_psk_from_file_secure, parse_hex_psk};

#[cfg(feature = "mcp")]
fn load_psk(psk_file: Option<&str>, psk_hex: Option<&str>) -> Result<Option<[u8; 16]>, String> {
    if let Some(path) = psk_file {
        let key = load_psk_from_file_secure(path)?;
        return Ok(Some(key));
    }

    if let Ok(env_val) = std::env::var("ILP_PSK_HEX") {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            let key = parse_hex_psk(trimmed)?;
            return Ok(Some(key));
        }
    }

    if let Some(hex_key) = psk_hex {
        eprintln!(
            "Aviso de seguridad [DEPRECATED/TEST-ONLY]: Pasar la clave PSK como argumento de línea de comandos es inseguro (visible en /proc y ps); use --psk-file o la variable de entorno ILP_PSK_HEX en producción."
        );
        let key = parse_hex_psk(hex_key)?;
        return Ok(Some(key));
    }

    Ok(None)
}

#[cfg(feature = "mcp")]
macro_rules! log_msg {
    ($use_stdio:expr, $($arg:tt)*) => {
        if $use_stdio {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    };
}

#[cfg(feature = "mcp")]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr_str = "127.0.0.1:9001".to_string();
    let mut listen_specified = false;
    let mut use_stdio = false;
    let mut gateway_addr_str = "127.0.0.1:9002".to_string();
    let mut policy_path = "policies/default_msac.conf".to_string();
    let mut initial_taint_str: Option<String> = None;
    let mut psk_str: Option<String> = None;
    let mut psk_file_path: Option<String> = None;
    let mut encrypt_payload = true;
    let mut audit_log_path: Option<String> = None;
    let mut trust_client_claims = false;
    let mut allow_non_loopback = false;
    let mut check_config_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--check-config" => {
                check_config_only = true;
                i += 1;
            }
            "--stdio" => {
                use_stdio = true;
                i += 1;
            }
            "--allow-non-loopback" => {
                allow_non_loopback = true;
                i += 1;
            }
            "--encrypt-payload" => {
                encrypt_payload = true;
                i += 1;
            }
            "--no-encrypt-payload" => {
                encrypt_payload = false;
                i += 1;
            }
            "--audit-log" => {
                if i + 1 < args.len() {
                    audit_log_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --audit-log requiere una ruta de archivo");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--audit-log=") => {
                audit_log_path = Some(opt.trim_start_matches("--audit-log=").to_string());
                i += 1;
            }
            "--trust-client-claims" => {
                trust_client_claims = true;
                i += 1;
            }
            "--listen" => {
                listen_specified = true;
                if i + 1 < args.len() {
                    listen_addr_str = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --listen requiere un argumento <IP:PUERTO>");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--listen=") => {
                listen_specified = true;
                listen_addr_str = opt.trim_start_matches("--listen=").to_string();
                i += 1;
            }
            "--gateway" => {
                if i + 1 < args.len() {
                    gateway_addr_str = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --gateway requiere un argumento <IP:PUERTO>");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--gateway=") => {
                gateway_addr_str = opt.trim_start_matches("--gateway=").to_string();
                i += 1;
            }
            "--policy" => {
                if i + 1 < args.len() {
                    policy_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --policy requiere una ruta");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--policy=") => {
                policy_path = opt.trim_start_matches("--policy=").to_string();
                i += 1;
            }
            "--initial-taint" => {
                if i + 1 < args.len() {
                    initial_taint_str = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --initial-taint requiere una lista de etiquetas");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--initial-taint=") => {
                initial_taint_str = Some(opt.trim_start_matches("--initial-taint=").to_string());
                i += 1;
            }
            "--psk-file" => {
                if i + 1 < args.len() {
                    psk_file_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --psk-file requiere una ruta de archivo");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--psk-file=") => {
                psk_file_path = Some(opt.trim_start_matches("--psk-file=").to_string());
                i += 1;
            }
            "--psk" => {
                if i + 1 < args.len() {
                    psk_str = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --psk requiere una clave hexadecimal de 32 caracteres");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--psk=") => {
                psk_str = Some(opt.trim_start_matches("--psk=").to_string());
                i += 1;
            }
            unknown => {
                eprintln!("Error: argumento desconocido '{}'", unknown);
                print_help();
                std::process::exit(1);
            }
        }
    }

    if use_stdio && listen_specified {
        eprintln!("Error: los modos --stdio y --listen son mutuamente excluyentes");
        std::process::exit(1);
    }

    // Validar direcciones de socket si no es modo stdio
    let mut listen_addr: Option<SocketAddr> = None;
    if !use_stdio {
        listen_addr = match listen_addr_str.parse() {
            Ok(addr) => Some(addr),
            Err(e) => {
                eprintln!(
                    "Error: formato de dirección --listen inválido '{}': {}",
                    listen_addr_str, e
                );
                std::process::exit(1);
            }
        };
    }
    if let Err(e) = gateway_addr_str.parse::<SocketAddr>() {
        eprintln!(
            "Error: formato de dirección --gateway inválido '{}': {}",
            gateway_addr_str, e
        );
        std::process::exit(1);
    }

    // Cargar PSK con orden de prioridad: --psk-file > ILP_PSK_HEX > --psk
    let parsed_psk = match load_psk(psk_file_path.as_deref(), psk_str.as_deref()) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error de clave PSK: {}", e);
            std::process::exit(1);
        }
    };

    // Guardarraíl de seguridad para interfaces de red no-loopback
    if let Some(l_addr) = listen_addr {
        if !l_addr.ip().is_loopback() && (!allow_non_loopback || parsed_psk.is_none()) {
            eprintln!(
                "Error de seguridad: el enlace a una interfaz de red no-loopback ({}) requiere la especificación explícita de --allow-non-loopback y una clave pre-compartida (vía --psk-file, ILP_PSK_HEX o --psk)",
                l_addr
            );
            std::process::exit(1);
        }
    }

    // Cargar y parsear la política
    let policy = match std::fs::read_to_string(&policy_path) {
        Ok(conf) => match UserGovernancePolicy::from_conf_str(&conf) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "Error al parsear el archivo de políticas '{}': {}",
                    policy_path, e
                );
                std::process::exit(1);
            }
        },
        Err(e) => {
            if check_config_only || policy_path != "policies/default_msac.conf" {
                eprintln!(
                    "Error: no se pudo leer el archivo de política '{}': {}",
                    policy_path, e
                );
                std::process::exit(1);
            }
            eprintln!(
                "Aviso: archivo de política default '{}' no encontrado ({}). Usando configuración integrada.",
                policy_path, e
            );
            UserGovernancePolicy::default()
        }
    };

    // Parsear etiquetas de tinte iniciales si fueron pasadas
    let mut initial_tags = Vec::new();
    if let Some(ref t_str) = initial_taint_str {
        for token in t_str.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            match TaintTag::from_name(trimmed) {
                Some(tag) => initial_tags.push((tag, trimmed.to_string())),
                None => {
                    eprintln!(
                        "Error: etiqueta de tinte desconocida en --initial-taint: '{}'",
                        trimmed
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    if check_config_only {
        println!("✓ Sintaxis de configuración y política MSAC validada exitosamente.");
        if use_stdio {
            println!("  - Mode:            stdio (stdin/stdout)");
        } else {
            println!("  - Listen Address:  {}", listen_addr_str);
        }
        println!("  - Gateway Address: {}", gateway_addr_str);
        println!("  - User DID:        {}", policy.user_did);
        println!("  - Max Budget Cap:  {}", policy.max_budget_cap);
        println!("  - Max Autonomy:    Tier {}", policy.max_autonomy_tier);
        println!(
            "  - Blacklisted:     {} habilidades",
            policy.blacklisted_skills.len()
        );
        println!(
            "  - PSK Auth:        {}",
            if parsed_psk.is_some() {
                "Habilitada (128 bits)"
            } else {
                "Deshabilitada"
            }
        );
        println!("  - Initial Taint:   {} etiquetas", initial_tags.len());
        println!("  - Trust Client Claims: {}", trust_client_claims);
        std::process::exit(0);
    }

    log_msg!(
        use_stdio,
        "╔══════════════════════════════════════════════════════════════════════════════╗"
    );
    log_msg!(
        use_stdio,
        "║   ILP MCP SIDECAR DAEMON - CAPA 8 (RFC-ILP-2026)                             ║"
    );
    log_msg!(
        use_stdio,
        "╚══════════════════════════════════════════════════════════════════════════════╝"
    );
    if use_stdio {
        log_msg!(use_stdio, "• Ingress MCP JSON-RPC:  stdio (stdin/stdout)");
    } else {
        log_msg!(use_stdio, "• Ingress MCP JSON-RPC:  {}", listen_addr_str);
    }
    log_msg!(use_stdio, "• Egress ILP I-PDU:      {}", gateway_addr_str);
    log_msg!(use_stdio, "• Archivo de Políticas:  {}", policy_path);
    log_msg!(use_stdio, "• DID de Gobernanza:     {}", policy.user_did);
    log_msg!(
        use_stdio,
        "• Autenticación PSK:     {}",
        if parsed_psk.is_some() {
            "Activa (SipHash-2-4)"
        } else {
            "Inactiva (Dev Mode)"
        }
    );
    log_msg!(
        use_stdio,
        "• Trust Client Claims:   {}",
        if trust_client_claims {
            "Habilitado (claims cliente aceptados)"
        } else {
            "Deshabilitado (default seguro)"
        }
    );

    let firewall = CognitiveFirewall::new(policy);
    let mut process_ctx = ProcessTaintContext::new(std::process::id(), "ilp_mcp_sidecar", true);

    for (tag, name) in initial_tags {
        log_msg!(use_stdio, "• Pre-manchado con Taint: {} ({})", name, tag);
        process_ctx.apply_taint(tag, &format!("cli:initial_taint:{}", name));
    }

    let taint_context = Arc::new(Mutex::new(process_ctx));

    let config = SidecarConfig {
        psk: parsed_psk,
        encrypt_payload,
        audit_log_path,
        trust_client_taint_claims: trust_client_claims,
        ..Default::default()
    };

    if use_stdio {
        log_msg!(
            use_stdio,
            "✓ Sidecar ejecutándose en modo transporte stdio (delimitado por líneas)."
        );
        if let Err(e) =
            McpSidecarServer::run_stdio(gateway_addr_str, firewall, taint_context, config)
        {
            eprintln!("[ERROR] Fallo en transporte stdio del Sidecar: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let server = match McpSidecarServer::start(
        &listen_addr_str,
        gateway_addr_str,
        firewall,
        taint_context,
        config,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Error al iniciar el servidor sidecar en '{}': {}",
                listen_addr_str, e
            );
            std::process::exit(1);
        }
    };

    println!("✓ Servidor Sidecar activo y escuchando en {}", server.addr);
    println!("Presiona Ctrl+C o envía SIGTERM para detener el daemon.\n");

    #[cfg(unix)]
    setup_signal_handlers();

    #[cfg(unix)]
    while !SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    #[cfg(not(unix))]
    loop {
        std::thread::park();
    }

    println!("\n[INFO] Señal de terminación recibida en Sidecar. Iniciando apagado ordenado...");
    server.shutdown();
    let m = server.metrics();
    println!(
        "[INFO] Apagado completado. Métricas finales: total_requests={}, accepted_connections={}, dropped_evaluations={}, auth_failures={}, replay_drops={}",
        m.total_requests, m.accepted_connections, m.dropped_evaluations, m.auth_failures, m.replay_drops
    );
    std::process::exit(0);
}

#[cfg(unix)]
static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_signal(_sig: std::os::raw::c_int) {
    SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
fn setup_signal_handlers() {
    unsafe {
        libc_signal(2, handle_signal); // SIGINT = 2
        libc_signal(15, handle_signal); // SIGTERM = 15
    }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "signal"]
    fn libc_signal(sig: std::os::raw::c_int, handler: extern "C" fn(std::os::raw::c_int)) -> usize;
}
