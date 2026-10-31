use ilp_core::ipdu::{CognitivePolicyFlags, IpduError, IpduPacket, MAX_ILP_PAYLOAD_SIZE};
use ilp_core::transport::IlpStream;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::thread;

#[test]
fn test_tcp_transport_roundtrip_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind al puerto efímero");
    let server_addr = listener.local_addr().expect("Obtener dirección local");

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("Aceptar conexión TCP");
        let mut ilp_stream = IlpStream::new(stream);

        // 1. Recibir DISCOVER_SKILL del cliente
        let req = ilp_stream
            .recv_packet()
            .expect("Servidor recibe DISCOVER_SKILL");
        assert_eq!(req.header.performative.to_string(), "DISCOVER_SKILL");
        assert_eq!(req.payload_as_str().unwrap(), "query:data-analysis");

        // 2. Responder con PROPOSE_INTENT
        let resp = IpduPacket::propose_intent(
            0xFEED_FACE_CAFE_BABE,
            req.header.session_uuid,
            2,
            500,
            5_000,
            CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE,
            0x1122_3344_5566_7788,
            r#"{"status":"ready","estimated_tokens":450}"#,
        )
        .expect("Construir propuesta");

        ilp_stream
            .send_packet(&resp)
            .expect("Servidor envía propuesta");
    });

    // Cliente
    let mut client_stream = IlpStream::connect(server_addr).expect("Conexión TCP cliente");

    let discover = IpduPacket::discover_skill(
        0xFEED_FACE_CAFE_BABE,
        0x1234_5678_9ABC_DEF0,
        CognitivePolicyFlags::EMPTY,
        "query:data-analysis",
    );

    client_stream
        .send_packet(&discover)
        .expect("Cliente envía DISCOVER_SKILL");

    let response = client_stream
        .recv_packet()
        .expect("Cliente recibe PROPOSE_INTENT");
    assert_eq!(response.header.performative.to_string(), "PROPOSE_INTENT");
    assert_eq!(response.header.max_budget_cap, 500);
    assert_eq!(response.header.session_uuid, 0x1234_5678_9ABC_DEF0);
    assert!(response.payload_as_str().unwrap().contains("ready"));

    server_handle
        .join()
        .expect("Servidor finalizó correctamente");
}

#[test]
fn test_tcp_transport_empty_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind");
    let server_addr = listener.local_addr().expect("Dirección");

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("Accept");
        let mut ilp_stream = IlpStream::new(stream);
        let pkt = ilp_stream.recv_packet().expect("Recibir paquete");
        assert_eq!(pkt.payload.len(), 0);
        ilp_stream.send_packet(&pkt).expect("Eco de paquete");
    });

    let mut client = IlpStream::connect(server_addr).expect("Connect");
    let empty_packet = IpduPacket::discover_skill(0x1111, 0x2222, CognitivePolicyFlags::EMPTY, "");

    client.send_packet(&empty_packet).expect("Enviar");
    let echoed = client.recv_packet().expect("Recibir eco");
    assert_eq!(echoed.payload.len(), 0);

    server.join().unwrap();
}

#[test]
fn test_tcp_transport_clean_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind");
    let server_addr = listener.local_addr().expect("Dirección");

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("Accept");
        let mut ilp_stream = IlpStream::new(stream);
        let err = ilp_stream
            .recv_packet()
            .expect_err("Debe detectar desconexión");
        assert_eq!(err, IpduError::ConnectionClosed);
    });

    // Cliente se conecta y se cierra inmediatamente
    {
        let _stream = TcpStream::connect(server_addr).expect("Connect");
    }

    server.join().unwrap();
}

#[test]
fn test_tcp_transport_allocation_bomb_rejection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind");
    let server_addr = listener.local_addr().expect("Dirección");

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("Accept");
        let mut ilp_stream = IlpStream::new(stream);
        let err = ilp_stream
            .recv_packet()
            .expect_err("Debe rechazar tamaño malicioso");
        match err {
            IpduError::PayloadTooLarge(len) => assert_eq!(len, MAX_ILP_PAYLOAD_SIZE + 1),
            other => panic!("Esperado PayloadTooLarge, obtenido {:?}", other),
        }
    });

    // Cliente malicioso envía cabecera válida pero longitud mayor a 64KB
    let mut raw_client = TcpStream::connect(server_addr).expect("Connect");
    let dummy = IpduPacket::discover_skill(0x1, 0x2, CognitivePolicyFlags::EMPTY, "");
    let mut bad_bytes = dummy.header.to_canonical_bytes().to_vec();
    let malformed_len = (MAX_ILP_PAYLOAD_SIZE as u32) + 1;
    bad_bytes.extend_from_slice(&malformed_len.to_be_bytes());

    raw_client
        .write_all(&bad_bytes)
        .expect("Enviar bytes maliciosos");
    raw_client.flush().expect("Flush");

    server.join().unwrap();
}
