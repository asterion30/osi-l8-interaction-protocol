//! RFC-ILP-2026: Capa 8 Interaction Protocol Performatives (Speech Acts)

use std::fmt;

/// Acto de habla agéntico estandarizado (6 bits, 0x00 .. 0x3F).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Performative {
    /// 0x01: Consulta de capacidades semánticas en la red (DHT / Semantic Edge Broker).
    DiscoverSkill = 0x01,
    /// 0x02: Propuesta de tarea u objetivo con condiciones de contorno y presupuesto inicial.
    ProposeIntent = 0x02,
    /// 0x03: Ajuste de precio, SLA, o restricciones técnicas entre agentes.
    CounterOffer = 0x03,
    /// 0x04: Aceptación formal y compromiso de ejecución bilateral con token de garantía.
    CommitContract = 0x04,
    /// 0x05: Rechazo de la interacción por violación de gobernanza o inviabilidad.
    RejectPolicy = 0x05,
    /// 0x06: Entrega de resultados con pruebas criptográficas verificables (VC / ZKP).
    AttestResult = 0x06,
}

impl Performative {
    /// Intenta instanciar una performativa desde su valor numérico de 6 bits.
    pub fn from_u8(value: u8) -> Result<Self, PerformativeError> {
        match value & 0x3F {
            0x01 => Ok(Self::DiscoverSkill),
            0x02 => Ok(Self::ProposeIntent),
            0x03 => Ok(Self::CounterOffer),
            0x04 => Ok(Self::CommitContract),
            0x05 => Ok(Self::RejectPolicy),
            0x06 => Ok(Self::AttestResult),
            other => Err(PerformativeError::UnknownPerformative(other)),
        }
    }

    /// Retorna el código numérico de 6 bits de la performativa.
    #[inline]
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Nombre mnemónico formal de la performativa.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DiscoverSkill => "DISCOVER_SKILL",
            Self::ProposeIntent => "PROPOSE_INTENT",
            Self::CounterOffer => "COUNTER_OFFER",
            Self::CommitContract => "COMMIT_CONTRACT",
            Self::RejectPolicy => "REJECT_POLICY",
            Self::AttestResult => "ATTEST_RESULT",
        }
    }
}

impl fmt::Display for Performative {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error al parsear una performativa desconocida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerformativeError {
    UnknownPerformative(u8),
}

impl fmt::Display for PerformativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPerformative(code) => {
                write!(f, "Performativa desconocida o no soportada: 0x{:02X}", code)
            }
        }
    }
}

impl std::error::Error for PerformativeError {}
