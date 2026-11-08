//! RFC-ILP-2026: I-PDU Frame MAC Authentication (SipHash-2-4)
//!
//! Proporciona autenticación criptográfica e integridad de trama en espacio de usuario
//! y kernel utilizando una clave pre-compartida (PSK) de 128 bits sin dependencias externas.

use super::header::IpduHeader;

/// Implementación canónica determinista de SipHash-2-4 de 64 bits (RFC 7693) en Rust estándar.
pub struct SipHash24 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    total_len: usize,
    buffer: [u8; 8],
    buf_len: usize,
}

#[inline(always)]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

impl SipHash24 {
    /// Inicializa una nueva instancia de SipHash-2-4 con una clave de 128 bits (`[u8; 16]`).
    pub fn new_with_key(key: &[u8; 16]) -> Self {
        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

        Self {
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
            total_len: 0,
            buffer: [0u8; 8],
            buf_len: 0,
        }
    }

    /// Alimenta datos arbitrarios al flujo hash.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len();

        if self.buf_len > 0 {
            let to_fill = 8 - self.buf_len;
            if data.len() < to_fill {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..8].copy_from_slice(&data[..to_fill]);
            let m = u64::from_le_bytes(self.buffer);
            self.process_word(m);
            self.buf_len = 0;
            data = &data[to_fill..];
        }

        while data.len() >= 8 {
            let m = u64::from_le_bytes(data[..8].try_into().unwrap());
            self.process_word(m);
            data = &data[8..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    #[inline(always)]
    fn process_word(&mut self, m: u64) {
        self.v3 ^= m;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= m;
    }

    /// Finaliza y produce el valor MAC de 64 bits.
    pub fn finish(mut self) -> u64 {
        let mut b: u64 = ((self.total_len & 0xff) as u64) << 56;
        for i in 0..self.buf_len {
            b |= (self.buffer[i] as u64) << (8 * i);
        }

        self.process_word(b);

        self.v2 ^= 0xff;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);

        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// Serializa los primeros 28 bytes inmutables de la cabecera canónica I-PDU:
/// - Word 0 (4 bytes)
/// - skill_namespace_hash (8 bytes)
/// - session_uuid (8 bytes)
/// - max_budget_cap (4 bytes)
/// - deadline_ttl_ms (4 bytes)
pub fn serialize_header_mac_input(header: &IpduHeader) -> [u8; 28] {
    let mut buf = [0u8; 28];
    buf[0..4].copy_from_slice(&header.pack_word0().to_be_bytes());
    buf[4..12].copy_from_slice(&header.skill_namespace_hash.to_be_bytes());
    buf[12..20].copy_from_slice(&header.session_uuid.to_be_bytes());
    buf[20..24].copy_from_slice(&header.max_budget_cap.to_be_bytes());
    buf[24..28].copy_from_slice(&header.deadline_ttl_ms.to_be_bytes());
    buf
}

/// Calcula el MAC de integridad de la trama I-PDU usando SipHash-2-4 con clave secreta de 128 bits.
/// Cubre los 28 bytes de la cabecera fija más la totalidad del payload.
pub fn compute_frame_mac(header: &IpduHeader, payload: &[u8], secret_key: &[u8; 16]) -> u64 {
    let mut hasher = SipHash24::new_with_key(secret_key);
    let hdr_bytes = serialize_header_mac_input(header);
    hasher.update(&hdr_bytes);
    hasher.update(payload);
    hasher.finish()
}

/// Verifica el MAC de integridad de una trama I-PDU en tiempo constante.
pub fn verify_frame_mac(
    header: &IpduHeader,
    payload: &[u8],
    secret_key: &[u8; 16],
    expected_mac: u64,
) -> bool {
    let computed = compute_frame_mac(header, payload, secret_key);
    // Comparación en tiempo constante para mitigar timing attacks
    let diff = computed ^ expected_mac;
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipdu::flags::CognitivePolicyFlags;
    use crate::ipdu::performatives::Performative;

    #[test]
    fn test_siphash24_mac_determinism_and_verification() {
        let key = [0x42u8; 16];
        let header = IpduHeader::new(
            Performative::ProposeIntent,
            2,
            CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE,
            0xA1B2_C3D4_E5F6_0789,
            0x1122_3344_5566_7788,
            10_000,
            5_000,
            0,
        )
        .unwrap();
        let payload = b"{\"intent\":\"secure_financial_transfer\"}";

        let mac1 = compute_frame_mac(&header, payload, &key);
        let mac2 = compute_frame_mac(&header, payload, &key);
        assert_eq!(mac1, mac2);
        assert_ne!(mac1, 0);

        assert!(verify_frame_mac(&header, payload, &key, mac1));

        // Clave equivocada debe fallar
        let wrong_key = [0x43u8; 16];
        assert!(!verify_frame_mac(&header, payload, &wrong_key, mac1));

        // Payload alterado debe fallar
        let tampered_payload = b"{\"intent\":\"hijacked_financial_transfer\"}";
        assert!(!verify_frame_mac(&header, tampered_payload, &key, mac1));
    }
}
