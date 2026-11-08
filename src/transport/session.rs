//! RFC-ILP-2026: Stateful Session Management & Finite State Machine (FSM)
//!
//! Este módulo formaliza la capa de sesión del protocolo ILP implementando una
//! Máquina de Estados Finita (FSM) determinista sobre el transporte binario `IlpStream`.
//!
//! Garantiza:
//! 1. Orden estricto de los actos de habla del 3-Way Intent Handshake.
//! 2. Validación y consistencia de `session_uuid`.
//! 3. Aplicación de timeouts de red derivados del `deadline_ttl_ms`.
//! 4. Transiciones atómicas y manejo limpio de errores y desconexiones.

use crate::ipdu::header::IpduError;
use crate::ipdu::packet::IpduPacket;
use crate::ipdu::performatives::Performative;
use crate::transport::IlpStream;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Causa de terminación o cierre de una sesión ILP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    /// Negociación y entrega de resultados completada exitosamente.
    Completed,
    /// El tiempo límite (deadline TTL) expiró antes de converger.
    Timeout,
    /// Violación de la secuencia de la máquina de estados o parámetros incompatibles.
    ProtocolViolation(String),
    /// La contraparte cerró la conexión TCP de forma ordenada o abrupta.
    PeerDisconnected,
    /// Interacción rechazada formalmente mediante `RejectPolicy`.
    Rejected,
}

/// Estados formales de la Máquina de Estados Finita (FSM) de una sesión ILP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Estado inicial: no hay negociación activa en el canal.
    Idle,
    /// Se ha emitido o recibido una consulta de habilidades semánticas (`DiscoverSkill`).
    DiscoverySent,
    /// Se ha propuesto un objetivo o contrato inicial (`ProposeIntent`).
    IntentProposed,
    /// Se está negociando activamente el precio, TTL o SLA (`CounterOffer`).
    CounterOffered,
    /// Se ha alcanzado un compromiso formal bilateral (`CommitContract`).
    ContractCommitted,
    /// La sesión ha finalizado y el canal no admite más transiciones activas.
    Terminated(TerminationReason),
}

impl SessionState {
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Terminated(_))
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::DiscoverySent => "DiscoverySent",
            Self::IntentProposed => "IntentProposed",
            Self::CounterOffered => "CounterOffered",
            Self::ContractCommitted => "ContractCommitted",
            Self::Terminated(_) => "Terminated",
        }
    }
}

/// Helper trait opcional para configurar timeouts sobre streams que lo soporten (como `TcpStream`).
pub trait SetSocketTimeout {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
}

impl SetSocketTimeout for TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_write_timeout(self, dur)
    }
}

/// Gestor de sesión con estado que encapsula un `IlpStream` y gobierna la FSM.
#[derive(Debug)]
pub struct IlpSession<S> {
    stream: IlpStream<S>,
    session_uuid: Option<u64>,
    state: SessionState,
    deadline_ttl_ms: u32,
}

impl<S> IlpSession<S> {
    /// Crea una nueva sesión ILP en estado `Idle`.
    pub fn new(stream: IlpStream<S>) -> Self {
        Self {
            stream,
            session_uuid: None,
            state: SessionState::Idle,
            deadline_ttl_ms: 0,
        }
    }

    /// Crea una sesión vinculada a un `session_uuid` predeterminado.
    pub fn with_session_uuid(stream: IlpStream<S>, session_uuid: u64) -> Self {
        Self {
            stream,
            session_uuid: Some(session_uuid),
            state: SessionState::Idle,
            deadline_ttl_ms: 0,
        }
    }

    /// Retorna el estado actual de la FSM.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Retorna el UUID de sesión actual, si ha sido fijado.
    pub fn session_uuid(&self) -> Option<u64> {
        self.session_uuid
    }

    /// Retorna una referencia inmutable al `IlpStream` interno.
    pub fn stream(&self) -> &IlpStream<S> {
        &self.stream
    }

    /// Retorna una referencia mutable al `IlpStream` interno.
    pub fn stream_mut(&mut self) -> &mut IlpStream<S> {
        &mut self.stream
    }

    /// Consume la sesión y retorna el stream de transporte subyacente.
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }

    /// Valida si una performativa es legal en el estado actual de la FSM y computa el siguiente estado.
    fn transition_state(
        &self,
        performative: Performative,
    ) -> Result<SessionState, IpduError> {
        match (&self.state, performative) {
            // Desde Idle: se puede iniciar descubrimiento o proponer un intent
            (SessionState::Idle, Performative::DiscoverSkill) => Ok(SessionState::DiscoverySent),
            (SessionState::Idle, Performative::ProposeIntent) => Ok(SessionState::IntentProposed),

            // Desde DiscoverySent: responder descubrimiento o lanzar intent
            (SessionState::DiscoverySent, Performative::DiscoverSkill) => {
                Ok(SessionState::DiscoverySent)
            }
            (SessionState::DiscoverySent, Performative::ProposeIntent) => {
                Ok(SessionState::IntentProposed)
            }
            (SessionState::DiscoverySent, Performative::RejectPolicy) => {
                Ok(SessionState::Terminated(TerminationReason::Rejected))
            }

            // Desde IntentProposed: contra-ofertar o comprometer contrato
            (SessionState::IntentProposed, Performative::CounterOffer) => {
                Ok(SessionState::CounterOffered)
            }
            (SessionState::IntentProposed, Performative::CommitContract) => {
                Ok(SessionState::ContractCommitted)
            }
            (SessionState::IntentProposed, Performative::RejectPolicy) => {
                Ok(SessionState::Terminated(TerminationReason::Rejected))
            }

            // Desde CounterOffered: re-negociar o comprometer contrato
            (SessionState::CounterOffered, Performative::CounterOffer) => {
                Ok(SessionState::CounterOffered)
            }
            (SessionState::CounterOffered, Performative::CommitContract) => {
                Ok(SessionState::ContractCommitted)
            }
            (SessionState::CounterOffered, Performative::RejectPolicy) => {
                Ok(SessionState::Terminated(TerminationReason::Rejected))
            }

            // Desde ContractCommitted: entrega de resultados ZKP/VC finaliza la sesión
            (SessionState::ContractCommitted, Performative::AttestResult) => {
                Ok(SessionState::Terminated(TerminationReason::Completed))
            }

            // En cualquier estado activo, recibir RejectPolicy aborta
            (state, Performative::RejectPolicy) if state.is_active() => {
                Ok(SessionState::Terminated(TerminationReason::Rejected))
            }

            // Cualquier otra combinación es una transición prohibida
            (current_state, perf) => Err(IpduError::InvalidStateTransition {
                current: format!("{:?}", current_state),
                received_performative: perf.to_string(),
            }),
        }
    }

    /// Verifica que el UUID de sesión del paquete coincida con la sesión activa.
    fn validate_session_uuid(&mut self, pkt_uuid: u64) -> Result<(), IpduError> {
        if let Some(expected) = self.session_uuid {
            if expected != pkt_uuid {
                return Err(IpduError::SessionMismatch {
                    expected,
                    actual: pkt_uuid,
                });
            }
        } else {
            // Se fija con el primer paquete que circula por la sesión
            self.session_uuid = Some(pkt_uuid);
        }
        Ok(())
    }
}

impl<S: Read + Write> IlpSession<S> {
    /// Envía un paquete I-PDU a través de la sesión validando la máquina de estados.
    pub fn send_packet(&mut self, packet: &IpduPacket) -> Result<(), IpduError> {
        if !self.state.is_active() {
            return Err(IpduError::InvalidStateTransition {
                current: format!("{:?}", self.state),
                received_performative: packet.header.performative.to_string(),
            });
        }

        self.validate_session_uuid(packet.header.session_uuid)?;
        let next_state = self.transition_state(packet.header.performative)?;

        self.stream.send_packet(packet)?;
        self.state = next_state;
        self.deadline_ttl_ms = packet.header.deadline_ttl_ms;
        Ok(())
    }

    /// Recibe un paquete I-PDU desde el canal validando framing, session_uuid y transiciones de la FSM.
    pub fn recv_packet(&mut self) -> Result<IpduPacket, IpduError> {
        if !self.state.is_active() {
            return Err(IpduError::InvalidStateTransition {
                current: format!("{:?}", self.state),
                received_performative: "RECV".to_string(),
            });
        }

        let packet = match self.stream.recv_packet() {
            Ok(pkt) => pkt,
            Err(IpduError::ConnectionClosed) => {
                self.state = SessionState::Terminated(TerminationReason::PeerDisconnected);
                return Err(IpduError::ConnectionClosed);
            }
            Err(IpduError::Io(ref msg))
                if msg.contains("timed out")
                    || msg.contains("Resource temporarily unavailable")
                    || msg.contains("WouldBlock") =>
            {
                self.state = SessionState::Terminated(TerminationReason::Timeout);
                return Err(IpduError::DeadlineExpired);
            }
            Err(e) => return Err(e),
        };

        if let Err(e) = self.validate_session_uuid(packet.header.session_uuid) {
            self.state =
                SessionState::Terminated(TerminationReason::ProtocolViolation(e.to_string()));
            return Err(e);
        }

        match self.transition_state(packet.header.performative) {
            Ok(next_state) => {
                self.state = next_state;
                self.deadline_ttl_ms = packet.header.deadline_ttl_ms;
                Ok(packet)
            }
            Err(e) => {
                self.state =
                    SessionState::Terminated(TerminationReason::ProtocolViolation(e.to_string()));
                Err(e)
            }
        }
    }
}

impl IlpSession<TcpStream> {
    /// Aplica los timeouts de lectura y escritura en el `TcpStream` subyacente
    /// calculados a partir de los milisegundos de deadline.
    pub fn apply_deadline_timeouts(&mut self, ttl_ms: u32) -> Result<(), IpduError> {
        let dur = if ttl_ms > 0 {
            Some(Duration::from_millis(ttl_ms as u64))
        } else {
            None
        };

        self.stream.get_ref().set_read_timeout(dur)?;
        self.stream.get_ref().set_write_timeout(dur)?;
        self.deadline_ttl_ms = ttl_ms;
        Ok(())
    }
}
