//! RFC-ILP-2026: I-PDU Fixed Header Structure & Serialization

use super::flags::CognitivePolicyFlags;
use super::performatives::{Performative, PerformativeError};
use std::fmt;

/// Versión actual estandarizada del protocolo ILP.
pub const ILP_VERSION_1: u8 = 0x01;

/// Tamaño de la cabecera canónica alineada a 32 bits con firma ZKP/DID completa de 64 bits (36 bytes / 288 bits).
pub const CANONICAL_HEADER_SIZE: usize = 36;

/// Tamaño de la cabecera compactada estricta de 256 bits (32 bytes) con firma truncada a 32 bits.
pub const COMPACT_256BIT_HEADER_SIZE: usize = 32;

/// Cabecera binaria fija de Capa 8 I-PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpduHeader {
    /// Versión del protocolo ILP (4 bits, 0x1 por defecto).
    pub version: u8,
    /// Acto de habla agéntico (6 bits).
    pub performative: Performative,
    /// Grado de independencia conferido al agente (6 bits, 0..63).
    pub autonomy_tier: u8,
    /// Máscara de bits de políticas cognitivas evaluables en kernel (16 bits).
    pub policy_flags: CognitivePolicyFlags,
    /// Huella LSH / SimHash de la habilidad semántica requerida u ofrecida (64 bits).
    pub skill_namespace_hash: u64,
    /// Identificador único de sesión y diálogo de negociación multi-turno (64 bits).
    pub session_uuid: u64,
    /// Límite máximo de gasto computacional / tokens / micro-pagos (32 bits).
    pub max_budget_cap: u32,
    /// Tiempo de vida en milisegundos tras el cual el paquete expira (32 bits).
    pub deadline_ttl_ms: u32,
    /// Firma criptográfica o compromiso ZK respaldado por la DID del usuario (64 bits).
    pub user_rule_sig_hash: u64,
}

impl IpduHeader {
    /// Crea una nueva cabecera I-PDU con valores validados.
    pub fn new(
        performative: Performative,
        autonomy_tier: u8,
        policy_flags: CognitivePolicyFlags,
        skill_namespace_hash: u64,
        session_uuid: u64,
        max_budget_cap: u32,
        deadline_ttl_ms: u32,
        user_rule_sig_hash: u64,
    ) -> Result<Self, IpduError> {
        if autonomy_tier > 63 {
            return Err(IpduError::InvalidAutonomyTier(autonomy_tier));
        }

        Ok(Self {
            version: ILP_VERSION_1,
            performative,
            autonomy_tier,
            policy_flags,
            skill_namespace_hash,
            session_uuid,
            max_budget_cap,
            deadline_ttl_ms,
            user_rule_sig_hash,
        })
    }

    /// Empaqueta los primeros 32 bits (Word 0) en Network Byte Order (Big-Endian).
    #[inline]
    pub fn pack_word0(&self) -> u32 {
        let v = (self.version as u32 & 0x0F) << 28;
        let p = (self.performative.as_u8() as u32 & 0x3F) << 22;
        let a = (self.autonomy_tier as u32 & 0x3F) << 16;
        let f = self.policy_flags.bits() as u32 & 0xFFFF;
        v | p | a | f
    }

    /// Desempaqueta los primeros 32 bits (Word 0).
    pub fn unpack_word0(word0: u32) -> Result<(u8, Performative, u8, CognitivePolicyFlags), IpduError> {
        let version = ((word0 >> 28) & 0x0F) as u8;
        if version != ILP_VERSION_1 {
            return Err(IpduError::UnsupportedVersion(version));
        }

        let perf_raw = ((word0 >> 22) & 0x3F) as u8;
        let performative = Performative::from_u8(perf_raw)?;

        let autonomy_tier = ((word0 >> 16) & 0x3F) as u8;
        let flags_raw = (word0 & 0xFFFF) as u16;
        let policy_flags = CognitivePolicyFlags::from_bits_truncate(flags_raw);

        Ok((version, performative, autonomy_tier, policy_flags))
    }

    /// Serializa la cabecera canónica a un búfer binario de 36 bytes (Network Byte Order).
    pub fn to_canonical_bytes(&self) -> [u8; CANONICAL_HEADER_SIZE] {
        let mut buf = [0u8; CANONICAL_HEADER_SIZE];

        let word0 = self.pack_word0();
        buf[0..4].copy_from_slice(&word0.to_be_bytes());
        buf[4..12].copy_from_slice(&self.skill_namespace_hash.to_be_bytes());
        buf[12..20].copy_from_slice(&self.session_uuid.to_be_bytes());
        buf[20..24].copy_from_slice(&self.max_budget_cap.to_be_bytes());
        buf[24..28].copy_from_slice(&self.deadline_ttl_ms.to_be_bytes());
        buf[28..36].copy_from_slice(&self.user_rule_sig_hash.to_be_bytes());

        buf
    }

    /// Serializa la cabecera en modo compacto de 32 bytes (256 bits estricto).
    /// En este modo, `user_rule_sig_hash` se trunca a sus 32 bits superiores.
    pub fn to_compact_256bit_bytes(&self) -> [u8; COMPACT_256BIT_HEADER_SIZE] {
        let mut buf = [0u8; COMPACT_256BIT_HEADER_SIZE];

        let word0 = self.pack_word0();
        buf[0..4].copy_from_slice(&word0.to_be_bytes());
        buf[4..12].copy_from_slice(&self.skill_namespace_hash.to_be_bytes());
        buf[12..20].copy_from_slice(&self.session_uuid.to_be_bytes());
        buf[20..24].copy_from_slice(&self.max_budget_cap.to_be_bytes());
        buf[24..28].copy_from_slice(&self.deadline_ttl_ms.to_be_bytes());
        let sig32 = (self.user_rule_sig_hash >> 32) as u32;
        buf[28..32].copy_from_slice(&sig32.to_be_bytes());

        buf
    }

    /// Deserializa la cabecera canónica de 36 bytes.
    pub fn from_canonical_bytes(buf: &[u8]) -> Result<Self, IpduError> {
        if buf.len() < CANONICAL_HEADER_SIZE {
            return Err(IpduError::BufferUnderflow {
                expected: CANONICAL_HEADER_SIZE,
                actual: buf.len(),
            });
        }

        let word0 = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let (version, performative, autonomy_tier, policy_flags) = Self::unpack_word0(word0)?;

        let skill_namespace_hash = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let session_uuid = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        let max_budget_cap = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        let deadline_ttl_ms = u32::from_be_bytes(buf[24..28].try_into().unwrap());
        let user_rule_sig_hash = u64::from_be_bytes(buf[28..36].try_into().unwrap());

        Ok(Self {
            version,
            performative,
            autonomy_tier,
            policy_flags,
            skill_namespace_hash,
            session_uuid,
            max_budget_cap,
            deadline_ttl_ms,
            user_rule_sig_hash,
        })
    }

    /// Deserializa la cabecera compacta de 32 bytes (256 bits).
    pub fn from_compact_bytes(buf: &[u8]) -> Result<Self, IpduError> {
        if buf.len() < COMPACT_256BIT_HEADER_SIZE {
            return Err(IpduError::BufferUnderflow {
                expected: COMPACT_256BIT_HEADER_SIZE,
                actual: buf.len(),
            });
        }

        let word0 = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let (version, performative, autonomy_tier, policy_flags) = Self::unpack_word0(word0)?;

        let skill_namespace_hash = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let session_uuid = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        let max_budget_cap = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        let deadline_ttl_ms = u32::from_be_bytes(buf[24..28].try_into().unwrap());
        let sig32 = u32::from_be_bytes(buf[28..32].try_into().unwrap());
        let user_rule_sig_hash = (sig32 as u64) << 32;

        Ok(Self {
            version,
            performative,
            autonomy_tier,
            policy_flags,
            skill_namespace_hash,
            session_uuid,
            max_budget_cap,
            deadline_ttl_ms,
            user_rule_sig_hash,
        })
    }
}

impl fmt::Display for IpduHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "I-PDU[v={:#x}, act={}, tier={}, flags=({}), skill={:#018x}, sess={:#018x}, budget={}, ttl={}ms, sig={:#018x}]",
            self.version,
            self.performative,
            self.autonomy_tier,
            self.policy_flags,
            self.skill_namespace_hash,
            self.session_uuid,
            self.max_budget_cap,
            self.deadline_ttl_ms,
            self.user_rule_sig_hash
        )
    }
}

/// Errores durante la validación o parsing de la I-PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpduError {
    UnsupportedVersion(u8),
    InvalidAutonomyTier(u8),
    Performative(PerformativeError),
    BufferUnderflow { expected: usize, actual: usize },
    InvalidPayloadLength { declared: usize, actual: usize },
    PayloadTooLarge(usize),
    ArithmeticOverflow,
    TruncatedPayload { expected: usize, actual: usize },
}

impl From<PerformativeError> for IpduError {
    fn from(err: PerformativeError) -> Self {
        Self::Performative(err)
    }
}

impl fmt::Display for IpduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "Versión ILP no soportada: 0x{:X}", v),
            Self::InvalidAutonomyTier(t) => write!(f, "Autonomy Tier fuera de rango (0..63): {}", t),
            Self::Performative(e) => write!(f, "Error en performativa: {}", e),
            Self::BufferUnderflow { expected, actual } => {
                write!(f, "Búfer insuficiente: esperado {} bytes, recibidos {}", expected, actual)
            }
            Self::InvalidPayloadLength { declared, actual } => {
                write!(f, "Longitud de payload inconsistente: declarada {}, real {}", declared, actual)
            }
            Self::PayloadTooLarge(len) => {
                write!(f, "Payload excede el límite máximo de protocolo ({} bytes)", len)
            }
            Self::ArithmeticOverflow => {
                write!(f, "Desbordamiento aritmético al calcular la longitud total de trama")
            }
            Self::TruncatedPayload { expected, actual } => {
                write!(f, "Trama truncada: esperado {} bytes totales, recibidos {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for IpduError {}
