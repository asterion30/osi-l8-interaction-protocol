//! RFC-ILP-2026: I-PDU Complete Packet Representation

use super::flags::CognitivePolicyFlags;
use super::header::{IpduError, IpduHeader, CANONICAL_HEADER_SIZE};
use super::performatives::Performative;
use std::fmt;

/// Paquete completo de Capa 8 I-PDU: Cabecera Fija + Prefijo de Longitud + Payload Semántico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpduPacket {
    /// Cabecera binaria estructurada de 36 bytes.
    pub header: IpduHeader,
    /// Carga útil semántica (representación de contexto, grafo o tensores de intención).
    pub payload: Vec<u8>,
}

impl IpduPacket {
    /// Construye un nuevo paquete I-PDU.
    pub fn new(header: IpduHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Longitud total del paquete serializado en bytes.
    #[inline]
    pub fn wire_len(&self) -> usize {
        CANONICAL_HEADER_SIZE + 4 + self.payload.len()
    }

    /// Serializa el paquete completo a un vector de bytes para transmisión en red.
    /// Formato: [Cabecera 36B] [Longitud Payload 4B Big-Endian] [Payload Variable...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.wire_len());
        bytes.extend_from_slice(&self.header.to_canonical_bytes());
        let payload_len = self.payload.len() as u32;
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserializa un paquete completo desde un búfer de red.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, IpduError> {
        if buf.len() < CANONICAL_HEADER_SIZE + 4 {
            return Err(IpduError::BufferUnderflow {
                expected: CANONICAL_HEADER_SIZE + 4,
                actual: buf.len(),
            });
        }

        let header = IpduHeader::from_canonical_bytes(&buf[0..CANONICAL_HEADER_SIZE])?;
        let payload_len = u32::from_be_bytes(
            buf[CANONICAL_HEADER_SIZE..CANONICAL_HEADER_SIZE + 4]
                .try_into()
                .unwrap(),
        ) as usize;

        let available_payload = buf.len() - (CANONICAL_HEADER_SIZE + 4);
        if available_payload < payload_len {
            return Err(IpduError::InvalidPayloadLength {
                declared: payload_len,
                actual: available_payload,
            });
        }

        let payload_start = CANONICAL_HEADER_SIZE + 4;
        let payload = buf[payload_start..payload_start + payload_len].to_vec();

        Ok(Self { header, payload })
    }

    /// Intenta interpretar el payload como texto UTF-8 (ej. JSON-LD o intención natural).
    pub fn payload_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.payload)
    }

    // --- Constructores Ergonómicos para el 3-Way Intent Handshake ---

    /// Crea un paquete `DISCOVER_SKILL` para descubrimiento semántico en la DHT.
    pub fn discover_skill(
        skill_hash: u64,
        session_uuid: u64,
        policy_flags: CognitivePolicyFlags,
        query_desc: &str,
    ) -> Self {
        let header = IpduHeader::new(
            Performative::DiscoverSkill,
            0, // Tier 0 consulta
            policy_flags,
            skill_hash,
            session_uuid,
            0,
            10_000, // 10s TTL
            0,
        )
        .expect("Parámetros válidos");
        Self::new(header, query_desc.as_bytes().to_vec())
    }

    /// Crea un paquete `PROPOSE_INTENT` con presupuesto y condiciones de contorno.
    pub fn propose_intent(
        skill_hash: u64,
        session_uuid: u64,
        autonomy_tier: u8,
        budget_cap: u32,
        ttl_ms: u32,
        policy_flags: CognitivePolicyFlags,
        sig_hash: u64,
        intent_payload: &str,
    ) -> Result<Self, IpduError> {
        let header = IpduHeader::new(
            Performative::ProposeIntent,
            autonomy_tier,
            policy_flags,
            skill_hash,
            session_uuid,
            budget_cap,
            ttl_ms,
            sig_hash,
        )?;
        Ok(Self::new(header, intent_payload.as_bytes().to_vec()))
    }

    /// Crea un paquete `COUNTER_OFFER` ajustando precio o SLA.
    pub fn counter_offer(
        session_uuid: u64,
        skill_hash: u64,
        counter_budget: u32,
        counter_ttl_ms: u32,
        sig_hash: u64,
        terms: &str,
    ) -> Result<Self, IpduError> {
        let header = IpduHeader::new(
            Performative::CounterOffer,
            1,
            CognitivePolicyFlags::EMPTY,
            skill_hash,
            session_uuid,
            counter_budget,
            counter_ttl_ms,
            sig_hash,
        )?;
        Ok(Self::new(header, terms.as_bytes().to_vec()))
    }

    /// Crea un paquete `COMMIT_CONTRACT` confirmando el acuerdo y escrow.
    pub fn commit_contract(
        session_uuid: u64,
        skill_hash: u64,
        final_budget: u32,
        sig_hash: u64,
        contract_details: &str,
    ) -> Result<Self, IpduError> {
        let header = IpduHeader::new(
            Performative::CommitContract,
            2,
            CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE,
            skill_hash,
            session_uuid,
            final_budget,
            30_000,
            sig_hash,
        )?;
        Ok(Self::new(header, contract_details.as_bytes().to_vec()))
    }
}

impl fmt::Display for IpduPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, PayloadLen={} bytes",
            self.header,
            self.payload.len()
        )
    }
}
