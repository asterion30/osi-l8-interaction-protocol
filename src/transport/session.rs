//! RFC-ILP-2026: Transport Session & Handshake Finite State Machine (FSM)
//!
//! Este módulo formaliza la capa de sesión y negociación bilateral de Capa 8:
//! 1. `IlpSession`: Gestor de sesión que gobierna el canal sobre cualquier `IlpStream`.
//! 2. `SessionState`: Estados finitos formales del 3-Way Intent Handshake (RFC-ILP-2026).
//! 3. `SessionRole`: Rol explícito en la negociación (`Initiator` o `Responder`), garantizando
//!    que solo el iniciador abra propuestas y que el servidor no emita contratos no solicitados.
//! 4. `TerminationReason`: Causa estricta de cierre de sesión (Completado, Rechazado, Timeout, Violación).

use super::IlpStream;
use crate::ipdu::header::IpduError;
use crate::ipdu::packet::IpduPacket;
use crate::ipdu::performatives::Performative;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Rol de la entidad en la sesión de negociación agéntica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Cliente / Agente demandante que inicia el descubrimiento o propone el objetivo.
    Initiator,
    /// Servidor / Agente proveedor que escucha, cotiza o ejecuta la habilidad.
    Responder,
}

/// Razones de finalización y desconexión de una sesión de Capa 8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    /// Negociación y ejecución completadas con éxito (`ATTEST_RESULT` confirmado).
    Completed,
    /// Rechazado por política de gobernanza o desacuerdo de términos (`REJECT_POLICY`).
    Rejected,
    /// Tiempo límite (deadline TTL) expirado antes de completar la interacción.
    Timeout,
    /// Violación de protocolo (ej. performativa fuera de orden o inconsistencia de UUID).
    ProtocolViolation(String),
    /// Desconexión limpia del par remoto.
    PeerDisconnected,
}

/// Estados finitos del 3-Way Intent Handshake (RFC-ILP-2026).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Canal establecido, listo para iniciar negociación.
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

/// Timeout por defecto para el handshake inicial del Responder (5.000 ms).
pub const DEFAULT_INITIAL_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Helper trait para configurar timeouts sobre streams que lo soporten (como `TcpStream`).
///
/// **Invariante de seguridad:** Elimina cuerpos silenciosos por defecto para forzar que todo
/// implementador configure verdaderamente el timeout del socket subyacente o devuelva error explícito.
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

impl<T> SetSocketTimeout for std::io::Cursor<T> {
    fn set_read_timeout(&self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _dur: Option<Duration>) -> std::io::Result<()> {
        Ok(())
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
    initial_handshake_timeout: Duration,
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
            initial_handshake_timeout: DEFAULT_INITIAL_HANDSHAKE_TIMEOUT,
        }
    }

    /// Configura el timeout de handshake inicial para proteger al Responder contra Slowloris.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.initial_handshake_timeout = timeout;
        self
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
            initial_handshake_timeout: DEFAULT_INITIAL_HANDSHAKE_TIMEOUT,
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
                SessionState::DiscoverySent,
                Performative::CounterOffer,
            ) => Ok(SessionState::CounterOffered),
            (
                SessionRole::Initiator,
                Direction::Recv,
                SessionState::DiscoverySent,
                Performative::ProposeIntent,
            ) => Ok(SessionState::IntentProposed),
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
                SessionState::DiscoverySent,
                Performative::CounterOffer,
            ) => Ok(SessionState::CounterOffered),
            (
                SessionRole::Responder,
                Direction::Send,
                SessionState::DiscoverySent,
                Performative::ProposeIntent,
            ) => Ok(SessionState::IntentProposed),
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
                current: format!("{:?} ({:?} {:?})", current_state, role, dir),
                received_performative: perf.to_string(),
            }),
        }
    }

    /// Verifica si el `session_uuid` del paquete entrante o saliente coincide con el de la sesión.
    fn check_session_uuid(&self, pkt_uuid: u64) -> Result<u64, IpduError> {
        match self.session_uuid {
            Some(expected) => {
                if pkt_uuid != expected {
                    Err(IpduError::SessionMismatch {
                        expected,
                        actual: pkt_uuid,
                    })
                } else {
                    Ok(expected)
                }
            }
            None => Ok(pkt_uuid),
        }
    }
}

impl<S: Read + Write + SetSocketTimeout> IlpSession<S> {
    /// Envía un paquete I-PDU a través de la sesión validando la máquina de estados de forma atómica.
    ///
    /// Aplica dinámicamente `remaining_duration()` como timeout de socket antes de la E/S.
    /// Solo muta `self.state`, `self.session_uuid` y `self.session_deadline` si la escritura en el socket tiene éxito.
    pub fn send_packet(&mut self, packet: &IpduPacket) -> Result<(), IpduError> {
        if !self.state.is_active() {
            return Err(IpduError::InvalidStateTransition {
                current: format!("{:?}", self.state),
                received_performative: packet.header().performative.to_string(),
            });
        }

        // 1. Calcular deadline candidato local sin mutar el estado permanentemente de antemano
        let (cand_deadline, cand_ttl) =
            if self.session_deadline.is_none() && packet.header().deadline_ttl_ms > 0 {
                let dur = Duration::from_millis(packet.header().deadline_ttl_ms as u64);
                (Some(Instant::now() + dur), packet.header().deadline_ttl_ms)
            } else {
                (self.session_deadline, self.deadline_ttl_ms)
            };

        // 2. Verificar y configurar deadline en el socket antes de enviar
        if let Some(dl) = cand_deadline {
            let now = Instant::now();
            if now >= dl {
                self.state = SessionState::Terminated(TerminationReason::Timeout);
                return Err(IpduError::DeadlineExpired);
            }
            self.stream.set_io_timeout(Some(dl - now))?;
        }

        // 3. Pre-validar consistencia de UUID y FSM sin mutar el estado
        let next_uuid = self.check_session_uuid(packet.header().session_uuid)?;
        let next_state = self.transition_state(packet.header().performative, Direction::Send)?;

        // 4. I/O en el stream subyacente
        self.stream.send_packet(packet)?;

        // 5. Mutación atómica post-éxito
        self.state = next_state;
        self.session_uuid = Some(next_uuid);
        self.session_deadline = cand_deadline;
        self.deadline_ttl_ms = cand_ttl;

        Ok(())
    }

    /// Recibe un paquete I-PDU desde el canal validando framing, session_uuid y transiciones de la FSM.
    ///
    /// Aplica `initial_handshake_timeout` en Responder en estado Idle (anti-Slowloris),
    /// y dinámicamente `remaining_duration()` una vez establecido el handshake.
    pub fn recv_packet(&mut self) -> Result<IpduPacket, IpduError> {
        if !self.state.is_active() {
            return Err(IpduError::InvalidStateTransition {
                current: format!("{:?}", self.state),
                received_performative: "RECV".to_string(),
            });
        }

        // 1. Configurar timeout antes de recibir:
        // Si el Responder está en Idle, protege contra Slowloris aplicando initial_handshake_timeout.
        if self.state == SessionState::Idle && self.role == SessionRole::Responder {
            self.stream
                .set_io_timeout(Some(self.initial_handshake_timeout))?;
        } else if let Some(rem) = self.remaining_duration() {
            if rem.is_zero() {
                self.state = SessionState::Terminated(TerminationReason::Timeout);
                return Err(IpduError::DeadlineExpired);
            }
            self.stream.set_io_timeout(Some(rem))?;
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
        let next_uuid = match self.check_session_uuid(packet.header().session_uuid) {
            Ok(uuid) => uuid,
            Err(e) => {
                self.state =
                    SessionState::Terminated(TerminationReason::ProtocolViolation(e.to_string()));
                return Err(e);
            }
        };

        // 4. Validación de transición legal de la FSM
        match self.transition_state(packet.header().performative, Direction::Recv) {
            Ok(next_state) => {
                // Mutación atómica post-validación
                self.state = next_state;
                self.session_uuid = Some(next_uuid);
                if packet.header().deadline_ttl_ms > 0 && self.session_deadline.is_none() {
                    self.set_deadline_ttl(packet.header().deadline_ttl_ms);
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

        self.stream.set_io_timeout(dur)?;
        Ok(())
    }
}
