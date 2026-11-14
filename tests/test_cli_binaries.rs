#![cfg(feature = "mcp")]

use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn test_sidecar_check_config_valid_and_invalid() {
    let sidecar_bin = env!("CARGO_BIN_EXE_ilp_mcp_sidecar");

    // 1. Archivo de políticas válido -> Exit Code 0
    let valid_status = Command::new(sidecar_bin)
        .args(["--check-config", "--policy", "policies/default_msac.conf"])
        .status()
        .expect("Execute ilp_mcp_sidecar");
    assert!(
        valid_status.success(),
        "Check-config con política válida debe salir con 0"
    );

    // 2. Archivo inexistente -> Exit Code != 0
    let invalid_status = Command::new(sidecar_bin)
        .args([
            "--check-config",
            "--policy",
            "policies/non_existent_policy.conf",
        ])
        .status()
        .expect("Execute ilp_mcp_sidecar");
    assert!(
        !invalid_status.success(),
        "Check-config con archivo inexistente debe fallar"
    );
}

#[test]
fn test_gateway_check_config() {
    let gateway_bin = env!("CARGO_BIN_EXE_ilp_mcp_gateway");

    let status = Command::new(gateway_bin)
        .args([
            "--check-config",
            "--psk",
            "00112233445566778899aabbccddeeff",
        ])
        .status()
        .expect("Execute ilp_mcp_gateway");
    assert!(
        status.success(),
        "Check-config del gateway debe salir con 0"
    );
}

#[test]
fn test_binaries_non_loopback_security_guardrail() {
    let sidecar_bin = env!("CARGO_BIN_EXE_ilp_mcp_sidecar");
    let gateway_bin = env!("CARGO_BIN_EXE_ilp_mcp_gateway");

    // Sidecar sin --allow-non-loopback en 0.0.0.0 debe ser rechazado
    let sc_status = Command::new(sidecar_bin)
        .args(["--listen", "0.0.0.0:9991"])
        .status()
        .expect("Execute ilp_mcp_sidecar");
    assert!(
        !sc_status.success(),
        "Sidecar en 0.0.0.0 sin flag debe ser bloqueado por seguridad"
    );

    // Gateway sin --allow-non-loopback en 0.0.0.0 debe ser rechazado
    let gw_status = Command::new(gateway_bin)
        .args(["--listen", "0.0.0.0:9992"])
        .status()
        .expect("Execute ilp_mcp_gateway");
    assert!(
        !gw_status.success(),
        "Gateway en 0.0.0.0 sin flag debe ser bloqueado por seguridad"
    );
}

#[test]
fn test_full_binary_e2e_authenticated_flow() {
    let sidecar_bin = env!("CARGO_BIN_EXE_ilp_mcp_sidecar");
    let gateway_bin = env!("CARGO_BIN_EXE_ilp_mcp_gateway");

    // 1. Levantar servidor simulado de backend MCP
    let mock_listener = TcpListener::bind("127.0.0.1:0").expect("Bind mock backend");
    let mock_addr = mock_listener.local_addr().unwrap().to_string();
    mock_listener.set_nonblocking(true).unwrap();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shut_clone = Arc::clone(&shutdown);

    thread::spawn(move || {
        while !shut_clone.load(Ordering::SeqCst) {
            if let Ok((stream, _)) = mock_listener.accept() {
                thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut writer = stream;
                    let mut line = String::new();
                    while let Ok(n) = reader.read_line(&mut line) {
                        if n == 0 {
                            break;
                        }
                        if let Ok(req) = serde_json::from_str::<serde_json::Value>(&line) {
                            let resp = json!({
                                "jsonrpc": "2.0",
                                "id": req.get("id").unwrap_or(&json!(1)),
                                "result": {
                                    "status": "binary_e2e_success",
                                    "echo": req.get("params").and_then(|p| p.get("arguments"))
                                }
                            });
                            let mut resp_str = resp.to_string();
                            resp_str.push('\n');
                            let _ = writer.write_all(resp_str.as_bytes());
                            let _ = writer.flush();
                        }
                        line.clear();
                    }
                });
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    // Obtener puertos únicos para Gateway y Sidecar sin pre-binding en el proceso actual
    use std::sync::atomic::AtomicU16;
    static BASE_PORT: AtomicU16 = AtomicU16::new(0);
    let offset = BASE_PORT.fetch_add(2, Ordering::SeqCst);
    let pid_offset = (std::process::id() as u16 % 500) * 4;
    let gw_port = 28000 + pid_offset + offset;
    let sc_port = gw_port + 1;

    let gw_addr = format!("127.0.0.1:{}", gw_port);
    let sc_addr = format!("127.0.0.1:{}", sc_port);
    let psk = "00112233445566778899aabbccddeeff";

    // 2. Levantar proceso Gateway real
    let gw_child = Command::new(gateway_bin)
        .args(["--listen", &gw_addr, "--backend", &mock_addr, "--psk", psk])
        .spawn()
        .expect("Spawn ilp_mcp_gateway");
    let _gw_guard = ChildGuard(gw_child);

    // 3. Levantar proceso Sidecar real
    let sc_child = Command::new(sidecar_bin)
        .args([
            "--listen",
            &sc_addr,
            "--gateway",
            &gw_addr,
            "--policy",
            "policies/default_msac.conf",
            "--psk",
            psk,
        ])
        .spawn()
        .expect("Spawn ilp_mcp_sidecar");
    let _sc_guard = ChildGuard(sc_child);

    // Esperar a que el sidecar esté listo para aceptar conexiones
    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(&sc_addr) {
            stream = Some(s);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let mut stream = stream.expect("No se pudo conectar al Sidecar iniciado como proceso hijo");

    // 4. Enviar llamada MCP JSON-RPC real a través de los dos procesos del sistema operativo
    let req = json!({
        "jsonrpc": "2.0",
        "id": "e2e-cli-001",
        "method": "tools/call",
        "params": {
            "name": "cli_test_tool",
            "arguments": { "msg": "Hello Subprocess ILP" }
        }
    });
    let mut payload = req.to_string();
    payload.push('\n');
    stream.write_all(payload.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .expect("Read subprocess response");

    let resp: serde_json::Value = serde_json::from_str(&resp_line).expect("Valid JSON response");
    assert_eq!(resp["id"], "e2e-cli-001");
    assert_eq!(resp["result"]["status"], "binary_e2e_success");
    assert_eq!(resp["result"]["echo"]["msg"], "Hello Subprocess ILP");

    shutdown.store(true, Ordering::SeqCst);
}

#[test]
fn test_cli_binaries_psk_file_and_env_loading() {
    let sidecar_bin = env!("CARGO_BIN_EXE_ilp_mcp_sidecar");
    let gateway_bin = env!("CARGO_BIN_EXE_ilp_mcp_gateway");

    let tmp_dir = std::env::temp_dir();
    let psk_path = tmp_dir.join(format!("test_ilp_psk_{}.key", std::process::id()));
    std::fs::write(&psk_path, "00112233445566778899aabbccddeeff\n").expect("Write PSK file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&psk_path, std::fs::Permissions::from_mode(0o600))
            .expect("Set 0600 permissions");
    }

    // 1. Carga válida desde archivo con permisos seguros (0600)
    let sc_status = Command::new(sidecar_bin)
        .args(["--check-config", "--psk-file", psk_path.to_str().unwrap()])
        .status()
        .expect("Execute sidecar with --psk-file");
    assert!(
        sc_status.success(),
        "Sidecar debe aceptar --psk-file con permisos 0600"
    );

    let gw_status = Command::new(gateway_bin)
        .args(["--check-config", "--psk-file", psk_path.to_str().unwrap()])
        .status()
        .expect("Execute gateway with --psk-file");
    assert!(
        gw_status.success(),
        "Gateway debe aceptar --psk-file con permisos 0600"
    );

    // 2. Rechazo por permisos inseguros (0666 en Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&psk_path, std::fs::Permissions::from_mode(0o666))
            .expect("Set 0666 permissions");

        let insecure_status = Command::new(sidecar_bin)
            .args(["--check-config", "--psk-file", psk_path.to_str().unwrap()])
            .status()
            .expect("Execute sidecar with insecure psk file");
        assert!(
            !insecure_status.success(),
            "Sidecar DEBE rechazar archivo PSK con permisos 0666 (inseguros)"
        );
    }

    // 3. Carga válida mediante variable de entorno ILP_PSK_HEX
    let env_status = Command::new(sidecar_bin)
        .args(["--check-config"])
        .env("ILP_PSK_HEX", "00112233445566778899aabbccddeeff")
        .status()
        .expect("Execute sidecar with ILP_PSK_HEX");
    assert!(
        env_status.success(),
        "Sidecar debe cargar clave desde ILP_PSK_HEX"
    );

    let _ = std::fs::remove_file(&psk_path);
}
