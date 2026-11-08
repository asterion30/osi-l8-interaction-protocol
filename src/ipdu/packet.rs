//! RFC-ILP-2026: I-PDU Complete Packet Representation

use super::flags::CognitivePolicyFlags;
use super::header::{IpduError, IpduHeader, CANONICAL_HEADER_SIZE};
use super::performatives::Performative;
use std::fmt;

/// Paquete completo de Capa 8 I-PDU: Cabecera Fija + Prefijo de Longitud + Payload Semántico.
///
/// Encapsulamiento estricto: los campos `header` y `payload` son privados para evitar
/// mutaciones no verificadas que violen las cotas de memoria (`MAX_ILP_PAYLOAD_SIZE = 64 KiB`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpduPacket {
    /// Cabecera binaria estructurada de 36 bytes.
    header: IpduHeader,
    /// Carga útil semántica (representación de contexto, grafo o tensores de intención).
    payload: Vec<u8>,
}

/// Límite duro de protocolo en Capa 8 (64 KB por I-PDU para evitar OOM en Kernel/Userspace).
pub const MAX_ILP_PAYLOAD_SIZE: usize = 65_536;

/// Verifica de forma determinista el prefijo de longitud sin reservar memoria en el heap.
pub fn validate_frame_bounds(raw: &[u8]) -> Result<usize, IpduError> {
    // 1. Verificación de tamaño mínimo (36 bytes cabecera + 4 bytes length prefix)
    if raw.len() < CANONICAL_HEADER_SIZE + 4 {
        return Err(IpduError::BufferUnderflow {
            expected: CANONICAL_HEADER_SIZE + 4,
            actual: raw.len(),
        });
    }

    // 2. Extracción segura sin indexación directa que pueda hacer panic
    let len_bytes: [u8; 4] = raw[CANONICAL_HEADER_SIZE..CANONICAL_HEADER_SIZE + 4]
        .try_into()
        .map_err(|_| IpduError::BufferUnderflow {
            expected: CANONICAL_HEADER_SIZE + 4,
            actual: raw.len(),
        })?;

    let payload_len = u32::from_be_bytes(len_bytes) as usize;

    // 3. Defensa contra Allocation Bomb (OOM)
    if payload_len > MAX_ILP_PAYLOAD_SIZE {
        return Err(IpduError::PayloadTooLarge(payload_len));
    }

    // 4. Verificación aritmética con checked_add para evitar Integer Overflow en 32-bit targets
    let total_expected = (CANONICAL_HEADER_SIZE + 4)
        .checked_add(payload_len)
        .ok_or(IpduError::ArithmeticOverflow)?;

    if raw.len() < total_expected {
        return Err(IpduError::TruncatedPayload {
            expected: total_expected,
            actual: raw.len(),
        });
    }

    // 5. Exigir exactitud de trama: prohibir bytes sobrantes (TrailingBytes)
    if raw.len() > total_expected {
        return Err(IpduError::TrailingBytes(raw.len() - total_expected));
    }

    Ok(payload_len)
}

impl IpduPacket {
    /// Intenta construir un nuevo paquete I-PDU validando cotas duras en el payload.
    pub fn try_new(header: IpduHeader, payload: Vec<u8>) -> Result<Self, IpduError> {
        if payload.len() > MAX_ILP_PAYLOAD_SIZE {
            return Err(IpduError::PayloadTooLarge(payload.len()));
        }
        Ok(Self { header, payload })
    }

    /// Construye un nuevo paquete I-PDU asegurando que jamás exceda 64 KiB en memoria.
    pub fn new(header: IpduHeader, payload: Vec<u8>) -> Self {
        Self::try_new(header, payload)
            .expect("El payload excede la cota máxima permitida (MAX_ILP_PAYLOAD_SIZE = 64 KiB)")
    }

    /// Retorna una referencia inmutable a la cabecera del paquete.
    #[inline]
    pub fn header(&self) -> &IpduHeader {
        &self.header
    }

    /// Retorna una referencia inmutable al payload del paquete.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Descompone el paquete consumiéndolo en su cabecera y payload.
    #[inline]
    pub fn into_parts(self) -> (IpduHeader, Vec<u8>) {
        (self.header, self.payload)
    }

    /// Actualiza el campo de firma/MAC `user_rule_sig_hash` de la cabecera.
    #[inline]
    pub fn set_user_rule_sig_hash(&mut self, sig_hash: u64) {
        self.header.user_rule_sig_hash = sig_hash;
    }

    /// Retorna una copia del paquete con el `user_rule_sig_hash` actualizado.
    #[inline]
    pub fn with_user_rule_sig_hash(mut self, sig_hash: u64) -> Self {
        self.header.user_rule_sig_hash = sig_hash;
        self
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

    /// Serializa de manera simétrica validando cotas estrictas.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, IpduError> {
        if self.payload.len() > MAX_ILP_PAYLOAD_SIZE {
            return Err(IpduError::PayloadTooLarge(self.payload.len()));
        }
        Ok(self.to_bytes())
    }

    /// Deserializa un paquete completo desde un búfer de red aplicando blindaje de cotas y exactitud de trama.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, IpduError> {
        let payload_len = validate_frame_bounds(buf)?;
        let header = IpduHeader::from_canonical_bytes(&buf[0..CANONICAL_HEADER_SIZE])?;

        let payload_start = CANONICAL_HEADER_SIZE + 4;
        let payload = buf[payload_start..payload_start + payload_len].to_vec();

        Self::try_new(header, payload)
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
    #[allow(clippy::too_many_arguments)]
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
        Self::try_new(header, intent_payload.as_bytes().to_vec())
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
        Self::try_new(header, terms.as_bytes().to_vec())
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
        Self::try_new(header, contract_details.as_bytes().to_vec())
    }

    /// Crea un paquete `REJECT_POLICY` notificando rechazo por violación de gobernanza.
    pub fn reject_policy(
        session_uuid: u64,
        skill_hash: u64,
        reason: &str,
    ) -> Result<Self, IpduError> {
        let header = IpduHeader::new(
            Performative::RejectPolicy,
            0,
            CognitivePolicyFlags::EMPTY,
            skill_hash,
            session_uuid,
            0,
            0,
            0,
        )?;
        Self::try_new(header, reason.as_bytes().to_vec())
    }

    /// Crea un paquete `ATTEST_RESULT` entregando pruebas criptográficas (VC / ZKP) del resultado.
    pub fn attest_result(
        session_uuid: u64,
        skill_hash: u64,
        autonomy_tier: u8,
        sig_hash: u64,
        proof_payload: &str,
    ) -> Result<Self, IpduError> {
        let header = IpduHeader::new(
            Performative::AttestResult,
            autonomy_tier,
            CognitivePolicyFlags::EMPTY,
            skill_hash,
            session_uuid,
            0,
            30_000,
            sig_hash,
        )?;
        Self::try_new(header, proof_payload.as_bytes().to_vec())
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
