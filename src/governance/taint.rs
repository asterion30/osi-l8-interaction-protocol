//! RFC-ILP-2026: Process Taint Tracking for Mandatory Semantic Access Control (MSAC)

use std::fmt;
use std::ops::{BitAnd, BitOr, BitXor, Not};

/// Etiquetas de clasificación de confidencialidad para el rastreo de tinte en el kernel/SO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct TaintTag(pub u32);

impl TaintTag {
    /// Proceso limpio sin interacción con datos sensibles.
    pub const CLEAN: Self = Self(0);

    /// Bit 0: Datos Médicos o Historiales Clínicos (HIPAA / GDPR Especial).
    pub const MEDICAL_PII: Self = Self(1 << 0);

    /// Bit 1: Datos Financieros, Cuentas Bancarias o Transacciones.
    pub const FINANCIAL_DATA: Self = Self(1 << 1);

    /// Bit 2: Datos Biométricos (Huellas, Reconocimiento Facial, Genómica).
    pub const BIOMETRIC_DATA: Self = Self(1 << 2);

    /// Bit 3: Credenciales de Acceso, Claves Privadas SSH/mTLS, Secretos API.
    pub const CREDENTIALS: Self = Self(1 << 3);

    /// Bit 4: Identificadores Gubernamentales (DNI, Pasaporte, SSN).
    pub const GOVERNMENT_ID: Self = Self(1 << 4);

    /// Bit 5: Propiedad Intelectual Confidencial o Código Propietario.
    pub const CONFIDENTIAL_IP: Self = Self(1 << 5);

    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn bits(&self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn is_clean(&self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn intersects(&self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

impl BitOr for TaintTag {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for TaintTag {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitXor for TaintTag {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Not for TaintTag {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl fmt::Display for TaintTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_clean() {
            return write!(f, "CLEAN");
        }
        let mut list = Vec::new();
        if self.contains(Self::MEDICAL_PII) {
            list.push("MEDICAL_PII");
        }
        if self.contains(Self::FINANCIAL_DATA) {
            list.push("FINANCIAL_DATA");
        }
        if self.contains(Self::BIOMETRIC_DATA) {
            list.push("BIOMETRIC_DATA");
        }
        if self.contains(Self::CREDENTIALS) {
            list.push("CREDENTIALS");
        }
        if self.contains(Self::GOVERNMENT_ID) {
            list.push("GOVERNMENT_ID");
        }
        if self.contains(Self::CONFIDENTIAL_IP) {
            list.push("CONFIDENTIAL_IP");
        }
        write!(f, "{}", list.join("|"))
    }
}

/// Capacidad máxima acotada para el historial de eventos de tinte en memoria.
pub const MAX_TAINT_HISTORY: usize = 64;

/// Evento auditable de contaminación de tinte con trazabilidad de origen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintEvent {
    /// Etiqueta asignada al proceso.
    pub tag: TaintTag,
    /// Descriptor de origen sanitizado (hasta 128 caracteres ASCII imprimibles).
    pub source_descriptor: String,
    /// Marca temporal en nanosegundos desde UNIX_EPOCH.
    pub timestamp_ns: u64,
}

/// Contexto de ejecución del proceso o agente emisor en el Sistema Operativo.
///
/// Invariante de seguridad: El tinte es estrictamente monótono creciente y sus campos
/// son privados para impedir que el código en espacio de usuario limpie o adultere la mancha.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessTaintContext {
    pid: u32,
    agent_name: String,
    taint: TaintTag,
    is_external_egress: bool,
    taint_history: Vec<TaintEvent>,
}

impl ProcessTaintContext {
    /// Crea un contexto de proceso inicialmente limpio.
    pub fn new(pid: u32, agent_name: impl Into<String>, is_external_egress: bool) -> Self {
        Self {
            pid,
            agent_name: agent_name.into(),
            taint: TaintTag::CLEAN,
            is_external_egress,
            taint_history: Vec::with_capacity(MAX_TAINT_HISTORY.min(16)),
        }
    }

    /// Retorna el PID del proceso o runtime del agente.
    #[inline]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Retorna el nombre mnemónico del agente.
    #[inline]
    pub fn agent_name(&self) -> &str {
        &self.agent_name
    }

    /// Retorna si el destino de la conexión es una interfaz externa / internet.
    #[inline]
    pub fn is_external_egress(&self) -> bool {
        self.is_external_egress
    }

    /// Retorna la máscara de bits de tinte actual acumulada por el proceso.
    #[inline]
    pub fn current_taint(&self) -> TaintTag {
        self.taint
    }

    /// Retorna si el proceso posee alguna de las etiquetas críticas dadas.
    #[inline]
    pub fn has_taint(&self, tag: TaintTag) -> bool {
        self.taint.intersects(tag)
    }

    /// Retorna una referencia inmutable a la secuencia de eventos de tinte registrados.
    #[inline]
    pub fn history(&self) -> &[TaintEvent] {
        &self.taint_history
    }

    /// Aplica una nueva etiqueta de tinte registrando formalmente el origen del evento.
    ///
    /// Invariante: El tinte solo puede expandirse, jamás reducirse o eliminarse.
    /// El descriptor de origen es truncado y sanitizado a 128 caracteres ASCII imprimibles.
    pub fn apply_taint(&mut self, new_tag: TaintTag, source: &str) {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let sanitized: String = source
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(128)
            .collect();

        self.taint = self.taint | new_tag;

        if self.taint_history.len() >= MAX_TAINT_HISTORY {
            self.taint_history.remove(0);
        }

        self.taint_history.push(TaintEvent {
            tag: new_tag,
            source_descriptor: sanitized,
            timestamp_ns: now_ns,
        });
    }

    /// Simula la lectura de un recurso clasificado en el filesystem (xattr/LSM hook).
    /// El tinte solo puede expandirse, nunca eliminarse por el propio proceso.
    pub fn contaminate_with(&mut self, new_tag: TaintTag) {
        self.apply_taint(new_tag, "unspecified_source");
    }

    /// Retorna un resumen formateado de los orígenes de la mancha.
    pub fn format_taint_sources(&self) -> String {
        if self.taint_history.is_empty() {
            return "none".to_string();
        }
        let descriptors: Vec<&str> = self
            .taint_history
            .iter()
            .map(|e| e.source_descriptor.as_str())
            .collect();
        descriptors.join(", ")
    }
}
