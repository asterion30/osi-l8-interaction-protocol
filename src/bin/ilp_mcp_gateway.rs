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
          --psk <HEX_KEY>            Clave pre-compartida de 128 bits (32 caracteres hexadecimales) para verificación MAC\n  \
          --allow-non-loopback       Permite enlazar a interfaces de red externas (requiere --psk)\n  \
          --check-config             Valida la configuración y sale con código 0\n  \
          -h, --help                 Muestra esta ayuda y finaliza\n"
    );
}

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("Error: el binario ilp_mcp_gateway requiere la feature 'mcp'.");
    eprintln!("Compila ejecutando: cargo build --bin ilp_mcp_gateway --features mcp");
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

    let mut listen_addr_str = "127.0.0.1:9002".to_string();
    let mut backend_addr_str = "127.0.0.1:8080".to_string();
    let mut max_conns = 128usize;
    let mut timeout_ms = 5000u64;
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

    let config = GatewayConfig {
        max_concurrent_connections: max_conns,
        io_timeout: Duration::from_millis(timeout_ms),
        psk: parsed_psk,
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
