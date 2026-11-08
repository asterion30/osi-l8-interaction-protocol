//! RFC-ILP-2026: Stateful Session Management & Finite State Machine (FSM)
//!
//! Este módulo formaliza la capa de sesión del protocolo ILP implementando una
//! Máquina de Estados Finita (FSM) determinista por roles (Initiator vs Responder)
//! sobre el transporte binario `IlpStream`.
//!
//! Garantiza:
//! 1. Orden estricto de los actos de habla del 3-Way Intent Handshake por rol y dirección.
//! 2. Mutación atómica de estado y session_uuid (solo tras I/O exitosa).
//! 3. Aplicación de timeouts de red derivados del `deadline_ttl_ms` y monotonic deadlines con `Instant`.
//! 4. Manejo estricto de desconexiones y eliminación de comparaciones de cadenas para errores de E/S.

use crate::ipdu::header::IpduError;
use crate::ipdu::packet::IpduPacket;
use crate::ipdu::performatives::Performative;
use crate::transport::IlpStream;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Rol asignado al nodo dentro de la sesión ILP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Inicia la interacción (Cliente / Agente Solicitante).
    Initiator,
    /// Responde a la interacción (Servidor / Agente Proveedor).
    Responder,
}

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
    #[inline]
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

/// Dirección de la trama I-PDU en el transporte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Send,
    Recv,
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
    role: SessionRole,
    session_uuid: Option<u64>,
    state: SessionState,
    session_deadline: Option<Instant>,
    deadline_ttl_ms: u32,
}

impl<S> IlpSession<S> {
    /// Crea una nueva sesión ILP asignándole un rol explícito (`Initiator` o `Responder`).
    pub fn new(stream: IlpStream<S>, role: SessionRole) -> Self {
        Self {
            stream,
            role,
            session_uuid: None,
            state: SessionState::Idle,
            session_deadline: None,
            deadline_ttl_ms: 0,
        }
    }

    /// Constructor ergonómico para una sesión en rol Initiator (Cliente).
    pub fn initiator(stream: IlpStream<S>) -> Self {
        Self::new(stream, SessionRole::Initiator)
    }

    /// Constructor ergonómico para una sesión en rol Responder (Servidor).
    pub fn responder(stream: IlpStream<S>) -> Self {
        Self::new(stream, SessionRole::Responder)
    }

    /// Crea una sesión vinculada a un `session_uuid` predeterminado.
    pub fn with_session_uuid(stream: IlpStream<S>, role: SessionRole, session_uuid: u64) -> Self {
        Self {
            stream,
            role,
            session_uuid: Some(session_uuid),
            state: SessionState::Idle,
            session_deadline: None,
            deadline_ttl_ms: 0,
        }
    }

    /// Retorna el rol asignado a la sesión.
    #[inline]
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// Retorna el estado actual de la FSM.
    #[inline]
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Retorna el UUID de sesión actual, si ha sido fijado.
    #[inline]
    pub fn session_uuid(&self) -> Option<u64> {
        self.session_uuid
    }

    /// Retorna una referencia inmutable al `IlpStream` interno.
    #[inline]
    pub fn stream(&self) -> &IlpStream<S> {
        &self.stream
    }

    /// Retorna una referencia mutable al `IlpStream` interno.
    #[inline]
    pub fn stream_mut(&mut self) -> &mut IlpStream<S> {
        &mut self.stream
    }

    /// Consume la sesión y retorna el stream de transporte subyacente.
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }

    /// Actualiza el deadline monotónico a partir del TTL en milisegundos.
    pub fn set_deadline_ttl(&mut self, ttl_ms: u32) {
        self.deadline_ttl_ms = ttl_ms;
        if ttl_ms > 0 {
            self.session_deadline = Some(Instant::now() + Duration::from_millis(ttl_ms as u64));
        } else {
            self.session_deadline = None;
        }
    }

    /// Calcula el tiempo restante antes de expirar el deadline.
    pub fn remaining_duration(&self) -> Option<Duration> {
        self.session_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Valida si una performativa es legal según el rol (`Initiator` o `Responder`) y la dirección (`Send` o `Recv`).
    fn transition_state(
        &self,
        performative: Performative,
        direction: Direction,
    ) -> Result<SessionState, IpduError> {
        // En cualquier estado activo, recibir o enviar RejectPolicy pasa a Terminated(Rejected)
        if performative == Performative::RejectPolicy && self.state.is_active() {
            return Ok(SessionState::Terminated(TerminationReason::Rejected));
        }

        match (self.role, direction, &self.state, performative) {
            // =================================================================
            // INITIATOR (CLIENTE)
            // =================================================================
            // Initiator SEND: Proponer o descubrir
            (
                SessionRole::Initiator,
                Direction::Send,
                SessionState::Idle,
                Performative::DiscoverSkill,
            ) => Ok(SessionState::DiscoverySent),
            (
                SessionRole::Initiator,
                Direction::Send,
                SessionState::Idle,
                Performative::ProposeIntent,
            ) => Ok(SessionState::IntentProposed),
            (
                SessionRole::Initiator,
                Direction::Send,
                SessionState::DiscoverySent,
                Performative::ProposeIntent,
            ) => Ok(SessionState::IntentProposed),
            // Initiator SEND: Confirmar contrato tras contraoferta o propuesta
            (
                SessionRole::Initiator,
                Direction::Send,
                SessionState::CounterOffered,
                Performative::CommitContract,
            ) => Ok(SessionState::ContractCommitted),
            (
                SessionRole::Initiator,
                Direction::Send,
                SessionState::CounterOffered,
                Performative::CounterOffer,
            ) => Ok(SessionState::CounterOffered),
            (
                SessionRole::Initiator,
                Direction::Send,
                SessionState::IntentProposed,
                Performative::CommitContract,
            ) => Ok(SessionState::ContractCommitted),

            // Initiator RECV: Respuestas del servidor
            (
                SessionRole::Initiator,
                Direction::Recv,
                SessionState::DiscoverySent,
                Performative::DiscoverSkill,
            ) => Ok(SessionState::DiscoverySent),
            (
                SessionRole::Initiator,
                Direction::Recv,
                SessionState::IntentProposed,
                Performative::CounterOffer,
            ) => Ok(SessionState::CounterOffered),
            (
                SessionRole::Initiator,
                Direction::Recv,
                SessionState::IntentProposed,
                Performative::CommitContract,
            ) => Ok(SessionState::ContractCommitted),
            (
                SessionRole::Initiator,
                Direction::Recv,
                SessionState::CounterOffered,
                Performative::CounterOffer,
            ) => Ok(SessionState::CounterOffered),
            (
                SessionRole::Initiator,
                Direction::Recv,
                SessionState::ContractCommitted,
                Performative::AttestResult,
            ) => Ok(SessionState::Terminated(TerminationReason::Completed)),

            // =================================================================
            // RESPONDER (SERVIDOR)
            // =================================================================
            // Responder RECV: Peticiones entrantes del cliente
            (
                SessionRole::Responder,
                Direction::Recv,
                SessionState::Idle,
                Performative::DiscoverSkill,
            ) => Ok(SessionState::DiscoverySent),
            (
                SessionRole::Responder,
                Direction::Recv,
                SessionState::Idle,
                Performative::ProposeIntent,
            ) => Ok(SessionState::IntentProposed),
            (
                SessionRole::Responder,
                Direction::Recv,
                SessionState::DiscoverySent,
                Performative::ProposeIntent,
            ) => Ok(SessionState::IntentProposed),
            (
                SessionRole::Responder,
                Direction::Recv,
                SessionState::CounterOffered,
                Performative::CommitContract,
            ) => Ok(SessionState::ContractCommitted),
            (
                SessionRole::Responder,
                Direction::Recv,
                SessionState::CounterOffered,
                Performative::CounterOffer,
            ) => Ok(SessionState::CounterOffered),
            (
                SessionRole::Responder,
                Direction::Recv,
                SessionState::IntentProposed,
                Performative::CommitContract,
            ) => Ok(SessionState::ContractCommitted),

            // Responder SEND: Respuestas hacia el cliente
            (
                SessionRole::Responder,
                Direction::Send,
                SessionState::DiscoverySent,
                Performative::DiscoverSkill,
            ) => Ok(SessionState::DiscoverySent),
            (
                SessionRole::Responder,
                Direction::Send,
                SessionState::IntentProposed,
                Performative::CounterOffer,
            ) => Ok(SessionState::CounterOffered),
            (
                SessionRole::Responder,
                Direction::Send,
                SessionState::IntentProposed,
                Performative::CommitContract,
            ) => Ok(SessionState::ContractCommitted),
            (
                SessionRole::Responder,
                Direction::Send,
                SessionState::CounterOffered,
                Performative::CounterOffer,
            ) => Ok(SessionState::CounterOffered),
            (
                SessionRole::Responder,
                Direction::Send,
                SessionState::ContractCommitted,
                Performative::AttestResult,
            ) => Ok(SessionState::Terminated(TerminationReason::Completed)),

            // Combinación ilegal
            (role, dir, current_state, perf) => Err(IpduError::InvalidStateTransition {
                current: format!("{:?} ({:?}, dir: {:?})", current_state, role, dir),
                received_performative: perf.to_string(),
            }),
        }
    }

    /// Valida que el UUID de sesión del paquete coincida con la sesión activa sin mutar el estado.
    fn check_session_uuid(&self, pkt_uuid: u64) -> Result<u64, IpduError> {
        if let Some(expected) = self.session_uuid {
            if expected != pkt_uuid {
                return Err(IpduError::SessionMismatch {
                    expected,
                    actual: pkt_uuid,
                });
            }
            Ok(expected)
        } else {
            Ok(pkt_uuid)
        }
    }
}

impl<S: Read + Write> IlpSession<S> {
    /// Envía un paquete I-PDU a través de la sesión validando la máquina de estados de forma atómica.
    ///
    /// Solo muta `self.state` y `self.session_uuid` si la escritura en el socket tiene éxito.
    pub fn send_packet(&mut self, packet: &IpduPacket) -> Result<(), IpduError> {
        if !self.state.is_active() {
            return Err(IpduError::InvalidStateTransition {
                current: format!("{:?}", self.state),
                received_performative: packet.header.performative.to_string(),
            });
        }

        // 1. Verificar deadline antes de enviar
        if let Some(rem) = self.remaining_duration() {
            if rem.is_zero() {
                self.state = SessionState::Terminated(TerminationReason::Timeout);
                return Err(IpduError::DeadlineExpired);
            }
        }

        // 2. Pre-validar consistencia de UUID y FSM sin mutar el estado
        let next_uuid = self.check_session_uuid(packet.header.session_uuid)?;
        let next_state = self.transition_state(packet.header.performative, Direction::Send)?;

        // 3. I/O en el stream subyacente
        self.stream.send_packet(packet)?;

        // 4. Mutación atómica post-éxito
        self.state = next_state;
        self.session_uuid = Some(next_uuid);
        if packet.header.deadline_ttl_ms > 0 && self.session_deadline.is_none() {
            self.set_deadline_ttl(packet.header.deadline_ttl_ms);
        }

        Ok(())
    }

    /// Recibe un paquete I-PDU desde el canal validando framing, session_uuid y transiciones de la FSM.
    ///
    /// Utiliza exclusivamente `std::io::ErrorKind` sin comparaciones de cadenas.
    pub fn recv_packet(&mut self) -> Result<IpduPacket, IpduError> {
        if !self.state.is_active() {
            return Err(IpduError::InvalidStateTransition {
                current: format!("{:?}", self.state),
                received_performative: "RECV".to_string(),
            });
        }

        // 1. Verificar deadline antes de recibir
        if let Some(rem) = self.remaining_duration() {
            if rem.is_zero() {
                self.state = SessionState::Terminated(TerminationReason::Timeout);
                return Err(IpduError::DeadlineExpired);
            }
        }

        // 2. I/O en el stream subyacente
        let packet = match self.stream.recv_packet() {
            Ok(pkt) => pkt,
            Err(IpduError::ConnectionClosed) => {
                self.state = SessionState::Terminated(TerminationReason::PeerDisconnected);
                return Err(IpduError::ConnectionClosed);
            }
            Err(IpduError::DeadlineExpired) => {
                self.state = SessionState::Terminated(TerminationReason::Timeout);
                return Err(IpduError::DeadlineExpired);
            }
            Err(e) => return Err(e),
        };

        // 3. Validación de consistencia de UUID
        let next_uuid = match self.check_session_uuid(packet.header.session_uuid) {
            Ok(uuid) => uuid,
            Err(e) => {
                self.state =
                    SessionState::Terminated(TerminationReason::ProtocolViolation(e.to_string()));
                return Err(e);
            }
        };

        // 4. Validación de transición legal de la FSM
        match self.transition_state(packet.header.performative, Direction::Recv) {
            Ok(next_state) => {
                // Mutación atómica post-validación
                self.state = next_state;
                self.session_uuid = Some(next_uuid);
                if packet.header.deadline_ttl_ms > 0 && self.session_deadline.is_none() {
                    self.set_deadline_ttl(packet.header.deadline_ttl_ms);
                }
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
        self.set_deadline_ttl(ttl_ms);
        let dur = if ttl_ms > 0 {
            Some(Duration::from_millis(ttl_ms as u64))
        } else {
            None
        };

        self.stream.get_ref().set_read_timeout(dur)?;
        self.stream.get_ref().set_write_timeout(dur)?;
        Ok(())
    }
}
