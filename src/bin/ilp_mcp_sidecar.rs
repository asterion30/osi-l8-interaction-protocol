//! Binario Desplegable: ILP MCP Sidecar Daemon (Capa 8 / RFC-ILP-2026)
//!
//! Intercepta tráfico Model Context Protocol (MCP) JSON-RPC, ejecuta el
//! Cognitive Reference Monitor (MSAC) en memoria (Zero-Connect) y reenvía
//! tráfico autorizado en formato binario I-PDU hacia el Gateway ILP.

#[cfg(feature = "mcp")]
use ilp_core::bridge::{McpSidecarServer, SidecarConfig};
#[cfg(feature = "mcp")]
use ilp_core::governance::{CognitiveFirewall, ProcessTaintContext, UserGovernancePolicy};
#[cfg(feature = "mcp")]
use std::net::SocketAddr;
#[cfg(feature = "mcp")]
use std::sync::{Arc, Mutex};

fn print_help() {
    println!(
        "Uso: ilp_mcp_sidecar [OPCIONES]\n\n\
        Opciones:\n  \
          --listen <IP:PUERTO>    Dirección de escucha para clientes MCP (default: 127.0.0.1:9001)\n  \
          --gateway <IP:PUERTO>   Dirección del Gateway ILP remoto (default: 127.0.0.1:9002)\n  \
          --policy <RUTA>         Ruta al archivo de políticas MSAC (default: policies/default_msac.conf)\n  \
          --check-config          Valida sintaxis de la política y configuración, saliendo con código 0\n  \
          -h, --help              Muestra esta ayuda y finaliza\n"
    );
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("Error: el binario ilp_mcp_sidecar requiere la feature 'mcp'.");
    eprintln!("Compila ejecutando: cargo build --bin ilp_mcp_sidecar --features mcp");
    std::process::exit(1);
}

#[cfg(feature = "mcp")]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr = "127.0.0.1:9001".to_string();
    let mut gateway_addr = "127.0.0.1:9002".to_string();
    let mut policy_path = "policies/default_msac.conf".to_string();
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
            "--listen" => {
                if i + 1 < args.len() {
                    listen_addr = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --listen requiere un argumento <IP:PUERTO>");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--listen=") => {
                listen_addr = opt.trim_start_matches("--listen=").to_string();
                i += 1;
            }
            "--gateway" => {
                if i + 1 < args.len() {
                    gateway_addr = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --gateway requiere un argumento <IP:PUERTO>");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--gateway=") => {
                gateway_addr = opt.trim_start_matches("--gateway=").to_string();
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
            unknown => {
                eprintln!("Error: argumento desconocido '{}'", unknown);
                print_help();
                std::process::exit(1);
            }
        }
    }

    // Validar direcciones de socket
    if let Err(e) = listen_addr.parse::<SocketAddr>() {
        eprintln!(
            "Error: formato de dirección --listen inválido '{}': {}",
            listen_addr, e
        );
        std::process::exit(1);
    }
    if let Err(e) = gateway_addr.parse::<SocketAddr>() {
        eprintln!(
            "Error: formato de dirección --gateway inválido '{}': {}",
            gateway_addr, e
        );
        std::process::exit(1);
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

    if check_config_only {
        println!("✓ Sintaxis de configuración y política MSAC validada exitosamente.");
        println!("  - Listen Address:  {}", listen_addr);
        println!("  - Gateway Address: {}", gateway_addr);
        println!("  - User DID:        {}", policy.user_did);
        println!("  - Max Budget Cap:  {}", policy.max_budget_cap);
        println!("  - Max Autonomy:    Tier {}", policy.max_autonomy_tier);
        println!(
            "  - Blacklisted:     {} habilidades",
            policy.blacklisted_skills.len()
        );
        std::process::exit(0);
    }

    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║   ILP MCP SIDECAR DAEMON - CAPA 8 (RFC-ILP-2026)                             ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!("• Ingress MCP JSON-RPC:  {}", listen_addr);
    println!("• Egress ILP I-PDU:      {}", gateway_addr);
    println!("• Archivo de Políticas:  {}", policy_path);
    println!("• DID de Gobernanza:     {}", policy.user_did);

    let firewall = CognitiveFirewall::new(policy);
    let taint_context = Arc::new(Mutex::new(ProcessTaintContext::new(
        std::process::id(),
        "ilp_mcp_sidecar",
        true,
    )));

    let config = SidecarConfig::default();

    let server = match McpSidecarServer::start(
        &listen_addr,
        gateway_addr,
        firewall,
        taint_context,
        config,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Error al iniciar el servidor sidecar en '{}': {}",
                listen_addr, e
            );
            std::process::exit(1);
        }
    };

    println!("✓ Servidor Sidecar activo y escuchando en {}", server.addr);
    println!("Presiona Ctrl+C para detener el daemon.\n");

    loop {
        std::thread::park();
    }
}
