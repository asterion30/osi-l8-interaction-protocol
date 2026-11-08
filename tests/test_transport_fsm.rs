//! RFC-ILP-2026: Transport Session & FSM Integration Tests

use ilp_core::ipdu::flags::CognitivePolicyFlags;
use ilp_core::ipdu::header::IpduError;
use ilp_core::ipdu::packet::IpduPacket;
use ilp_core::transport::{IlpSession, IlpStream, SessionState, TerminationReason};
use std::io::Cursor;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[test]
fn test_fsm_rejects_out_of_sequence_commit_in_idle() {
    let buf = Cursor::new(Vec::new());
    let stream = IlpStream::new(buf);
    let mut session = IlpSession::new(stream);

    assert_eq!(*session.state(), SessionState::Idle);

    // Intentar enviar COMMIT_CONTRACT en estado Idle es ilegal según la FSM
    let invalid_commit = IpduPacket::commit_contract(
        0x1111_2222_3333_4444,
        0xAAAA_BBBB_CCCC_DDDD,
        1000,
        0xCAFE_BABE,
        r#"{"escrow_token":"tok_123"}"#,
    )
    .unwrap();

    let res = session.send_packet(&invalid_commit);
    assert!(res.is_err());

    match res.unwrap_err() {
        IpduError::InvalidStateTransition {
            current,
            received_performative,
        } => {
            assert_eq!(current, "Idle");
            assert_eq!(received_performative, "COMMIT_CONTRACT");
        }
        other => panic!("Esperado InvalidStateTransition, recibido: {:?}", other),
    }

    // El estado sigue siendo Idle tras el fallo de validación
    assert_eq!(*session.state(), SessionState::Idle);
}

#[test]
fn test_fsm_rejects_session_uuid_mismatch() {
    let session_uuid_1 = 0xAAAA_1111_2222_3333;
    let session_uuid_2 = 0xBBBB_9999_8888_7777;

    let buf = Cursor::new(Vec::new());
    let stream = IlpStream::new(buf);
    let mut session = IlpSession::with_session_uuid(stream, session_uuid_1);

    // Intentar enviar con session_uuid_2 debe fallar
    let packet_mismatch = IpduPacket::propose_intent(
        0x1234,
        session_uuid_2,
        1,
        100,
        1000,
        CognitivePolicyFlags::EMPTY,
        0x5678,
        "test payload",
    )
    .unwrap();

    let res = session.send_packet(&packet_mismatch);
    assert!(res.is_err());

    match res.unwrap_err() {
        IpduError::SessionMismatch { expected, actual } => {
            assert_eq!(expected, session_uuid_1);
            assert_eq!(actual, session_uuid_2);
        }
        other => panic!("Esperado SessionMismatch, recibido: {:?}", other),
    }
}

#[test]
fn test_fsm_happy_path_handshake_transitions() {
    let session_uuid = 0x4242_CAFE_BABE_0001;

    let mut client_buf = Vec::new();
    let client_stream = IlpStream::new(Cursor::new(&mut client_buf));
    let mut client_session = IlpSession::with_session_uuid(client_stream, session_uuid);

    // 1. Propose Intent -> IntentProposed
    let propose = IpduPacket::propose_intent(
        0xABCD,
        session_uuid,
        2,
        500,
        10_000,
        CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE,
        0x1234,
        "need translate model",
    )
    .unwrap();

    client_session.send_packet(&propose).unwrap();
    assert_eq!(*client_session.state(), SessionState::IntentProposed);

    // 2. Counter Offer -> CounterOffered
    let counter = IpduPacket::counter_offer(
        session_uuid,
        0xABCD,
        450,
        8_000,
        0x1234,
        "offer 450 credits",
    )
    .unwrap();

    client_session.send_packet(&counter).unwrap();
    assert_eq!(*client_session.state(), SessionState::CounterOffered);

    // 3. Commit Contract -> ContractCommitted
    let commit = IpduPacket::commit_contract(
        session_uuid,
        0xABCD,
        450,
        0x1234,
        "committed",
    )
    .unwrap();

    client_session.send_packet(&commit).unwrap();
    assert_eq!(*client_session.state(), SessionState::ContractCommitted);

    // 4. Attest Result -> Terminated(Completed)
    let attest = IpduPacket::attest_result(
        session_uuid,
        0xABCD,
        2,
        0x1234,
        "result ZKP hash",
    )
    .unwrap();

    client_session.send_packet(&attest).unwrap();
    assert_eq!(
        *client_session.state(),
        SessionState::Terminated(TerminationReason::Completed)
    );

    // Cualquier nuevo paquete posterior a la terminación debe ser rechazado
    let after_term = client_session.send_packet(&propose);
    assert!(after_term.is_err());
}

#[test]
fn test_fsm_tcp_read_timeout_expiration() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind ephemeral listener");
    let addr = listener.local_addr().unwrap();

    // Servidor que acepta la conexión pero se duerme sin enviar datos
    let server_handle = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        // Duerme 200 ms, superando el TTL de 40 ms del cliente
        thread::sleep(Duration::from_millis(200));
    });

    let tcp_client = TcpStream::connect(addr).expect("Connect to server");
    let mut session = IlpSession::new(IlpStream::new(tcp_client));

    // Configuramos timeout a 40 ms
    session.apply_deadline_timeouts(40).expect("Set timeouts");

    let res = session.recv_packet();
    assert!(res.is_err());
    match res.unwrap_err() {
        IpduError::DeadlineExpired => {}
        other => panic!("Esperado DeadlineExpired, recibido: {:?}", other),
    }

    assert_eq!(
        *session.state(),
        SessionState::Terminated(TerminationReason::Timeout)
    );

    server_handle.join().unwrap();
}

#[test]
fn test_fsm_clean_disconnect_termination() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind ephemeral listener");
    let addr = listener.local_addr().unwrap();

    // Servidor acepta y cierra inmediatamente el socket
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        drop(stream);
    });

    let tcp_client = TcpStream::connect(addr).expect("Connect to server");
    let mut session = IlpSession::new(IlpStream::new(tcp_client));

    let res = session.recv_packet();
    assert_eq!(res.unwrap_err(), IpduError::ConnectionClosed);
    assert_eq!(
        *session.state(),
        SessionState::Terminated(TerminationReason::PeerDisconnected)
    );

    server_handle.join().unwrap();
}
