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

/// Contexto de ejecución del proceso o agente emisor en el Sistema Operativo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessTaintContext {
    /// Identificador del proceso (PID) o runtime del agente.
    pub pid: u32,
    /// Nombre mnemónico del agente.
    pub agent_name: String,
    /// Máscara acumulativa de tinte (propagación monotónica inmutable).
    pub taint: TaintTag,
    /// Destino de la conexión (true si es red pública / internet externo).
    pub is_external_egress: bool,
}

impl ProcessTaintContext {
    /// Crea un contexto de proceso inicialmente limpio.
    pub fn new(pid: u32, agent_name: impl Into<String>, is_external_egress: bool) -> Self {
        Self {
            pid,
            agent_name: agent_name.into(),
            taint: TaintTag::CLEAN,
            is_external_egress,
        }
    }

    /// Simula la lectura de un recurso clasificado en el filesystem (xattr/LSM hook).
    /// El tinte solo puede expandirse, nunca eliminarse por el propio proceso.
    pub fn contaminate_with(&mut self, new_tag: TaintTag) {
        self.taint = self.taint | new_tag;
    }

    /// Retorna si el proceso posee alguna de las etiquetas críticas dadas.
    #[inline]
    pub fn has_taint(&self, tag: TaintTag) -> bool {
        self.taint.intersects(tag)
    }
}
