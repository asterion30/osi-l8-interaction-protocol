//! Binario Desplegable: ILP MCP Gateway Daemon (Capa 8 / RFC-ILP-2026)
//!
//! Recibe tramas binarias I-PDU sobre sockets TCP, valida la autenticación de firma MAC
//! y despacha llamadas JSON-RPC al servidor de herramientas MCP de backend.

#[cfg(feature = "mcp")]
use ilp_core::bridge::{GatewayConfig, McpGatewayServer};
#[cfg(feature = "mcp")]
use std::net::SocketAddr;
#[cfg(feature = "mcp")]
use std::time::Duration;

fn print_help() {
    println!(
        "Uso: ilp_mcp_gateway [OPCIONES]\n\n\
        Opciones:\n  \
          --listen <IP:PUERTO>       Dirección de escucha para tramas binarias I-PDU (default: 127.0.0.1:9002)\n  \
          --backend <IP:PUERTO>      Dirección del servidor de herramientas MCP local (default: 127.0.0.1:8080)\n  \
          --max-conns <N>            Máximo de conexiones concurrentes permitidas (default: 128)\n  \
          --timeout-ms <MS>          Tiempo límite para operaciones de E/S en milisegundos (default: 5000)\n  \
          --psk-file <RUTA>          Carga clave pre-compartida de 128 bits desde archivo (requiere permisos 0600 o 0400)\n  \
          --psk <HEX_KEY>            [DEPRECATED/TEST-ONLY] Clave pre-compartida en línea de comandos (visible en /proc)\n  \
          --psk-previous-file <RUTA> Carga clave PSK previa para rotación sin interrupciones (Zero-Downtime Key Rotation)\n  \
          --psk-previous <HEX_KEY>   [TEST-ONLY] Clave PSK previa en hexadecimal (32 caracteres)\n  \
          --audit-log <RUTA>         Ruta para archivo de log forense estructurado en formato JSONL para SIEM\n  \
          --allow-non-loopback       Permite enlazar a interfaces de red externas (requiere PSK)\n  \
          --check-config             Valida la configuración y sale con código 0\n  \
          -h, --help                 Muestra esta ayuda y finaliza\n\n\
        Variables de entorno:\n  \
          ILP_PSK_HEX                Clave pre-compartida de 128 bits (32 dígitos hexadecimales)\n  \
          ILP_PSK_PREVIOUS_HEX       Clave pre-compartida previa para rotación de claves en caliente\n"
    );
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("Error: el binario ilp_mcp_gateway requiere la feature 'mcp'.");
    eprintln!("Compila ejecutando: cargo build --bin ilp_mcp_gateway --features mcp");
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
fn load_previous_psk(
    psk_file: Option<&str>,
    psk_hex: Option<&str>,
) -> Result<Option<[u8; 16]>, String> {
    if let Some(path) = psk_file {
        let key = load_psk_from_file_secure(path)?;
        return Ok(Some(key));
    }

    if let Ok(env_val) = std::env::var("ILP_PSK_PREVIOUS_HEX") {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            let key = parse_hex_psk(trimmed)?;
            return Ok(Some(key));
        }
    }

    if let Some(hex_key) = psk_hex {
        let key = parse_hex_psk(hex_key)?;
        return Ok(Some(key));
    }

    Ok(None)
}

#[cfg(feature = "mcp")]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr_str = "127.0.0.1:9002".to_string();
    let mut backend_addr_str = "127.0.0.1:8080".to_string();
    let mut max_conns = 128usize;
    let mut timeout_ms = 5000u64;
    let mut psk_str: Option<String> = None;
    let mut psk_file_path: Option<String> = None;
    let mut psk_previous_str: Option<String> = None;
    let mut psk_previous_file_path: Option<String> = None;
    let mut audit_log_path: Option<String> = None;
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
            "--psk-previous-file" => {
                if i + 1 < args.len() {
                    psk_previous_file_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --psk-previous-file requiere una ruta de archivo");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--psk-previous-file=") => {
                psk_previous_file_path =
                    Some(opt.trim_start_matches("--psk-previous-file=").to_string());
                i += 1;
            }
            "--psk-previous" => {
                if i + 1 < args.len() {
                    psk_previous_str = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!(
                        "Error: --psk-previous requiere una clave hexadecimal de 32 caracteres"
                    );
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--psk-previous=") => {
                psk_previous_str = Some(opt.trim_start_matches("--psk-previous=").to_string());
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
            "--backend" => {
                if i + 1 < args.len() {
                    backend_addr_str = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --backend requiere un argumento <IP:PUERTO>");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--backend=") => {
                backend_addr_str = opt.trim_start_matches("--backend=").to_string();
                i += 1;
            }
            "--max-conns" => {
                if i + 1 < args.len() {
                    max_conns = args[i + 1].parse().unwrap_or_else(|e| {
                        eprintln!("Error: --max-conns inválido: {}", e);
                        std::process::exit(1);
                    });
                    i += 2;
                } else {
                    eprintln!("Error: --max-conns requiere un valor numérico");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--max-conns=") => {
                max_conns = opt
                    .trim_start_matches("--max-conns=")
                    .parse()
                    .unwrap_or_else(|e| {
                        eprintln!("Error: --max-conns inválido: {}", e);
                        std::process::exit(1);
                    });
                i += 1;
            }
            "--timeout-ms" => {
                if i + 1 < args.len() {
                    timeout_ms = args[i + 1].parse().unwrap_or_else(|e| {
                        eprintln!("Error: --timeout-ms inválido: {}", e);
                        std::process::exit(1);
                    });
                    i += 2;
                } else {
                    eprintln!("Error: --timeout-ms requiere un valor numérico");
                    std::process::exit(1);
                }
            }
            opt if opt.starts_with("--timeout-ms=") => {
                timeout_ms = opt
                    .trim_start_matches("--timeout-ms=")
                    .parse()
                    .unwrap_or_else(|e| {
                        eprintln!("Error: --timeout-ms inválido: {}", e);
                        std::process::exit(1);
                    });
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
    if let Err(e) = backend_addr_str.parse::<SocketAddr>() {
        eprintln!(
            "Error: formato de dirección --backend inválido '{}': {}",
            backend_addr_str, e
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

    // Cargar PSK previa para rotación sin downtime (Zero-Downtime Key Rotation)
    let parsed_psk_previous = match load_previous_psk(
        psk_previous_file_path.as_deref(),
        psk_previous_str.as_deref(),
    ) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error de clave PSK previa: {}", e);
            std::process::exit(1);
        }
    };

    // Guardarraíl de seguridad para interfaces de red no-loopback
    if !listen_addr.ip().is_loopback() && (!allow_non_loopback || parsed_psk.is_none()) {
        eprintln!(
            "Error de seguridad: el enlace a una interfaz de red no-loopback ({}) requiere la especificación explícita de --allow-non-loopback y una clave pre-compartida (vía --psk-file, ILP_PSK_HEX o --psk)",
            listen_addr
        );
        std::process::exit(1);
    }

    if check_config_only {
        println!("✓ Configuración del Gateway ILP validada exitosamente.");
        println!("  - Listen Address:  {}", listen_addr);
        println!("  - Backend Target:  {}", backend_addr_str);
        println!("  - Max Conns:       {}", max_conns);
        println!("  - Timeout:         {} ms", timeout_ms);
        println!(
            "  - PSK Auth:        {}",
            if parsed_psk.is_some() {
                "Habilitada (128 bits)"
            } else {
                "Deshabilitada"
            }
        );
        println!(
            "  - Dual-PSK:        {}",
            if parsed_psk_previous.is_some() {
                "Habilitada (Rotación sin downtime)"
            } else {
                "Inactiva"
            }
        );
        std::process::exit(0);
    }

    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║   ILP MCP GATEWAY DAEMON - CAPA 8 (RFC-ILP-2026)                             ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!("• Ingress ILP I-PDU:     {}", listen_addr);
    println!("• Backend MCP Tool:      {}", backend_addr_str);
    println!("• Conexiones Máximas:    {}", max_conns);
    println!("• Timeout de E/S:        {} ms", timeout_ms);
    println!(
        "• Verificación PSK:      {}",
        if parsed_psk.is_some() {
            "Activa (SipHash-2-4)"
        } else {
            "Inactiva (Dev Mode)"
        }
    );
    if parsed_psk_previous.is_some() {
        println!("• Dual-PSK Rotación:     Activa (Clave previa registrada)");
    }

    let config = GatewayConfig {
        max_concurrent_connections: max_conns,
        io_timeout: Duration::from_millis(timeout_ms),
        psk: parsed_psk,
        psk_previous: parsed_psk_previous,
        audit_log_path,
        ..Default::default()
    };

    let server = match McpGatewayServer::start(&listen_addr_str, backend_addr_str, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Error al iniciar el servidor gateway en '{}': {}",
                listen_addr_str, e
            );
            std::process::exit(1);
        }
    };

    println!("✓ Servidor Gateway activo y escuchando en {}", server.addr);
    println!("Presiona Ctrl+C para detener el daemon.\n");

    loop {
        std::thread::park();
    }
}
