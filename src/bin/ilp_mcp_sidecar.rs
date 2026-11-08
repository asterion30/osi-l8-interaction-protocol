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
          --gateway <IP:PUERTO>      Dirección del Gateway ILP remoto (default: 127.0.0.1:9002)\n  \
          --policy <RUTA>            Ruta al archivo de políticas MSAC (default: policies/default_msac.conf)\n  \
          --initial-taint <TAGS>     Etiquetas iniciales de tinte separadas por coma (ej. medical_pii,financial_data)\n  \
          --psk <HEX_KEY>            Clave pre-compartida de 128 bits (32 caracteres hexadecimales) para firma de tramas\n  \
          --allow-non-loopback       Permite enlazar a interfaces de red externas (requiere --psk)\n  \
          --check-config             Valida sintaxis de la política y configuración, saliendo con código 0\n  \
          -h, --help                 Muestra esta ayuda y finaliza\n"
    );
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("Error: el binario ilp_mcp_sidecar requiere la feature 'mcp'.");
    eprintln!("Compila ejecutando: cargo build --bin ilp_mcp_sidecar --features mcp");
    std::process::exit(1);
}

#[cfg(feature = "mcp")]
fn parse_hex_psk(hex_str: &str) -> Result<[u8; 16], String> {
    let trimmed = hex_str
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if trimmed.len() != 32 {
        return Err(format!(
            "La clave PSK debe contener exactamente 32 dígitos hexadecimales (128 bits), se recibieron {}",
            trimmed.len()
        ));
    }
    let mut key = [0u8; 16];
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        key[i] = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("Valor hexadecimal inválido '{}': {}", pair, e))?;
    }
    Ok(key)
}

#[cfg(feature = "mcp")]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr_str = "127.0.0.1:9001".to_string();
    let mut gateway_addr_str = "127.0.0.1:9002".to_string();
    let mut policy_path = "policies/default_msac.conf".to_string();
    let mut initial_taint_str: Option<String> = None;
    let mut psk_str: Option<String> = None;
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
            "--allow-non-loopback" => {
                allow_non_loopback = true;
                i += 1;
            }
            "--listen" => {
                if i + 1 < args.len() {
                    listen_addr_str = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --listen requiere un argumento <IP:PUERTO>");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--listen=") => {
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

    // Validar direcciones de socket
    let listen_addr: SocketAddr = match listen_addr_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!(
                "Error: formato de dirección --listen inválido '{}': {}",
                listen_addr_str, e
            );
            std::process::exit(1);
        }
    };
    if let Err(e) = gateway_addr_str.parse::<SocketAddr>() {
        eprintln!(
            "Error: formato de dirección --gateway inválido '{}': {}",
            gateway_addr_str, e
        );
        std::process::exit(1);
    }

    // Parsear PSK si fue proporcionada
    let parsed_psk = match psk_str {
        Some(ref s) => match parse_hex_psk(s) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("Error: --psk inválida: {}", e);
                std::process::exit(1);
            }
        },
        None => None,
    };

    // Guardarraíl de seguridad para interfaces de red no-loopback
    if !listen_addr.ip().is_loopback() && (!allow_non_loopback || parsed_psk.is_none()) {
        eprintln!(
            "Error de seguridad: el enlace a una interfaz de red no-loopback ({}) requiere la especificación explícita de --allow-non-loopback y una clave pre-compartida (--psk <HEX_KEY>)",
            listen_addr
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
        println!("  - Listen Address:  {}", listen_addr);
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
        std::process::exit(0);
    }

    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║   ILP MCP SIDECAR DAEMON - CAPA 8 (RFC-ILP-2026)                             ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!("• Ingress MCP JSON-RPC:  {}", listen_addr);
    println!("• Egress ILP I-PDU:      {}", gateway_addr_str);
    println!("• Archivo de Políticas:  {}", policy_path);
    println!("• DID de Gobernanza:     {}", policy.user_did);
    println!(
        "• Autenticación PSK:     {}",
        if parsed_psk.is_some() {
            "Activa (SipHash-2-4)"
        } else {
            "Inactiva (Dev Mode)"
        }
    );

    let firewall = CognitiveFirewall::new(policy);
    let mut process_ctx = ProcessTaintContext::new(std::process::id(), "ilp_mcp_sidecar", true);

    for (tag, name) in initial_tags {
        println!("• Pre-manchado con Taint: {} ({})", name, tag);
        process_ctx.apply_taint(tag, &format!("cli:initial_taint:{}", name));
    }

    let taint_context = Arc::new(Mutex::new(process_ctx));

    let config = SidecarConfig {
        psk: parsed_psk,
        ..Default::default()
    };

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
    println!("Presiona Ctrl+C para detener el daemon.\n");

    loop {
        std::thread::park();
    }
}
