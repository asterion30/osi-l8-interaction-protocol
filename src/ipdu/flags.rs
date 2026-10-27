//! RFC-ILP-2026: Cognitive Policy Flags (16-bit bitmask)

use std::fmt;
use std::ops::{BitAnd, BitOr, BitXor, Not};

/// Máscara de bits de 16 bits evaluable en hardware/kernel para prevención de fuga de datos (DLP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct CognitivePolicyFlags(pub u16);

impl CognitivePolicyFlags {
    /// Sin restricciones de política activadas.
    pub const EMPTY: Self = Self(0);

    /// Bit 0: Prohíbe terminantemente la exfiltración de datos personalmente identificables (PII).
    pub const DENY_EGRESS_PII: Self = Self(1 << 0);

    /// Bit 1: Prohíbe el envío de información bancaria, balances o datos de tarjetas de crédito.
    pub const DENY_EGRESS_FINANCIAL: Self = Self(1 << 1);

    /// Bit 2: Obliga al nodo receptor a ejecutar la inferencia en un entorno de sandbox confinado.
    pub const REQUIRE_SANDBOXED_INFERENCE: Self = Self(1 << 2);

    /// Bit 3: Permite o prohíbe que el agente receptor sub-delegue tareas en terceros.
    pub const ALLOW_DELEGATION: Self = Self(1 << 3);

    /// Bit 4: El payload semántico viaja con cifrado extremo a extremo de Capa 8.
    pub const ENCRYPTED_PAYLOAD: Self = Self(1 << 4);

    /// Bit 5: La I-PDU contiene bloques TLV de extensión antes del payload semántico.
    pub const HAS_EXTENSIONS: Self = Self(1 << 5);

    /// Crea un conjunto de flags a partir del entero u16.
    #[inline]
    pub const fn from_bits_truncate(bits: u16) -> Self {
        Self(bits)
    }

    /// Retorna la representación entera de 16 bits.
    #[inline]
    pub const fn bits(&self) -> u16 {
        self.0
    }

    /// Verifica si contiene todos los flags especificados.
    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Verifica si se intersecta con alguno de los flags dados.
    #[inline]
    pub const fn intersects(&self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Inserta flags.
    #[inline]
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Remueve flags.
    #[inline]
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

impl BitOr for CognitivePolicyFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for CognitivePolicyFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitXor for CognitivePolicyFlags {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Not for CognitivePolicyFlags {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl fmt::Display for CognitivePolicyFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.contains(Self::DENY_EGRESS_PII) {
            flags.push("DENY_EGRESS_PII");
        }
        if self.contains(Self::DENY_EGRESS_FINANCIAL) {
            flags.push("DENY_EGRESS_FINANCIAL");
        }
        if self.contains(Self::REQUIRE_SANDBOXED_INFERENCE) {
            flags.push("REQUIRE_SANDBOXED_INFERENCE");
        }
        if self.contains(Self::ALLOW_DELEGATION) {
            flags.push("ALLOW_DELEGATION");
        }
        if self.contains(Self::ENCRYPTED_PAYLOAD) {
            flags.push("ENCRYPTED_PAYLOAD");
        }
        if self.contains(Self::HAS_EXTENSIONS) {
            flags.push("HAS_EXTENSIONS");
        }
        if flags.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", flags.join("|"))
        }
    }
}
