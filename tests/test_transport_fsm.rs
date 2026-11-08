//! RFC-ILP-2026: Transport Session & FSM Integration Tests

use ilp_core::ipdu::flags::CognitivePolicyFlags;
use ilp_core::ipdu::header::IpduError;
use ilp_core::ipdu::packet::IpduPacket;
use ilp_core::transport::{IlpSession, IlpStream, SessionRole, SessionState, TerminationReason};
use std::io::{self, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Canal bidireccional simple en memoria para pruebas de transporte sin sockets de red.
struct DuplexPipe {
    reader: mpsc::Receiver<u8>,
    writer: mpsc::Sender<u8>,
}

impl DuplexPipe {
    fn pair() -> (Self, Self) {
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        (
            DuplexPipe {
                reader: rx1,
                writer: tx2,
            },
            DuplexPipe {
                reader: rx2,
                writer: tx1,
            },
        )
    }
}

impl Read for DuplexPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let first = self
            .reader
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "canal cerrado"))?;
        buf[0] = first;
        let mut count = 1;
        while count < buf.len() {
            match self.reader.try_recv() {
                Ok(byte) => {
                    buf[count] = byte;
                    count += 1;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        Ok(count)
    }
}

impl Write for DuplexPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &byte in buf {
            self.writer
                .send(byte)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "receptor desconectado"))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_fsm_rejects_out_of_sequence_commit_in_idle() {
    let buf = Cursor::new(Vec::new());
    let stream = IlpStream::new(buf);
    let mut session = IlpSession::initiator(stream);

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
            assert!(current.contains("Idle"));
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
    let mut session = IlpSession::with_session_uuid(stream, SessionRole::Initiator, session_uuid_1);

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
fn test_fsm_happy_path_handshake_transitions_bidirectional() {
    let session_uuid = 0x4242_CAFE_BABE_0001;

    let (pipe_client, pipe_server) = DuplexPipe::pair();

    let mut client_session = IlpSession::with_session_uuid(
        IlpStream::new(pipe_client),
        SessionRole::Initiator,
        session_uuid,
    );
    let mut server_session = IlpSession::with_session_uuid(
        IlpStream::new(pipe_server),
        SessionRole::Responder,
        session_uuid,
    );

    // 1. Cliente envía PROPOSE_INTENT
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

    // Servidor recibe PROPOSE_INTENT
    let recv_propose = server_session.recv_packet().unwrap();
    assert_eq!(recv_propose, propose);
    assert_eq!(*server_session.state(), SessionState::IntentProposed);

    // 2. Servidor envía COUNTER_OFFER
    let counter = IpduPacket::counter_offer(
        session_uuid,
        0xABCD,
        450,
        8_000,
        0x1234,
        "offer 450 credits",
    )
    .unwrap();

    server_session.send_packet(&counter).unwrap();
    assert_eq!(*server_session.state(), SessionState::CounterOffered);

    // Cliente recibe COUNTER_OFFER
    let recv_counter = client_session.recv_packet().unwrap();
    assert_eq!(recv_counter, counter);
    assert_eq!(*client_session.state(), SessionState::CounterOffered);

    // 3. Cliente envía COMMIT_CONTRACT
    let commit =
        IpduPacket::commit_contract(session_uuid, 0xABCD, 450, 0x1234, "committed").unwrap();

    client_session.send_packet(&commit).unwrap();
    assert_eq!(*client_session.state(), SessionState::ContractCommitted);

    // Servidor recibe COMMIT_CONTRACT
    let recv_commit = server_session.recv_packet().unwrap();
    assert_eq!(recv_commit, commit);
    assert_eq!(*server_session.state(), SessionState::ContractCommitted);

    // 4. Servidor envía ATTEST_RESULT
    let attest =
        IpduPacket::attest_result(session_uuid, 0xABCD, 2, 0x1234, "result ZKP hash").unwrap();

    server_session.send_packet(&attest).unwrap();
    assert_eq!(
        *server_session.state(),
        SessionState::Terminated(TerminationReason::Completed)
    );

    // Cliente recibe ATTEST_RESULT
    let recv_attest = client_session.recv_packet().unwrap();
    assert_eq!(recv_attest, attest);
    assert_eq!(
        *client_session.state(),
        SessionState::Terminated(TerminationReason::Completed)
    );

    // Cualquier nuevo paquete posterior a la terminación debe ser rechazado en ambos lados
    assert!(client_session.send_packet(&propose).is_err());
    assert!(server_session.send_packet(&attest).is_err());
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
    let mut session = IlpSession::initiator(IlpStream::new(tcp_client));

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
    let mut session = IlpSession::initiator(IlpStream::new(tcp_client));

    let res = session.recv_packet();
    assert_eq!(res.unwrap_err(), IpduError::ConnectionClosed);
    assert_eq!(
        *session.state(),
        SessionState::Terminated(TerminationReason::PeerDisconnected)
    );

    server_handle.join().unwrap();
}
