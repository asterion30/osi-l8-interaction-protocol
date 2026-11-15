//! RFC-ILP-2026 / RFC 8439: Cifrador de Flujo ChaCha20 en Rust Puro (Zero Dependencies)
//!
//! Implementa la función de bloque ChaCha20 y el cifrado de flujo estándar de 20 rondas
//! según la especificación del RFC 8439 Sección 2.3 y 2.4.
//!
//! **Invariantes Criptográficos:**
//! - Cero dependencias externas (`std` puro, compatible con MSRV 1.70.0).
//! - Operaciones de rotación y suma acotada (`wrapping_add`, `rotate_left`, `^`).
//! - Derivación determinista de clave de 256 bits a partir de PSK de 128 o 256 bits.
//! - Nonces de 96 bits derivados de la cabecera I-PDU con dominio disjunto para solicitud y respuesta.

/// Constantes canónicas del RFC 8439: "expand 32-byte k"
const CHACHA20_CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// Operación de cuarto de ronda (Quarter Round) de ChaCha20 (RFC 8439 Sección 2.1).
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Ejecuta la función de bloque ChaCha20 de 20 rondas (RFC 8439 Sección 2.3).
/// Genera un bloque de flujo de 64 bytes pseudoaleatorios a partir de clave, contador y nonce.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    let mut state = [0u32; 16];

    // Palabras 0..3: Constantes
    state[0] = CHACHA20_CONSTANTS[0];
    state[1] = CHACHA20_CONSTANTS[1];
    state[2] = CHACHA20_CONSTANTS[2];
    state[3] = CHACHA20_CONSTANTS[3];

    // Palabras 4..11: Clave de 256 bits (8 palabras u32 Little-Endian)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Palabra 12: Contador de bloque de 32 bits
    state[12] = counter;

    // Palabras 13..15: Nonce de 96 bits (3 palabras u32 Little-Endian)
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    let mut working = state;

    // 10 iteraciones de 2 rondas cada una = 20 rondas totales
    for _ in 0..10 {
        // Rondas de columna
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);

        // Rondas diagonales
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    // Suma modular final con el estado inicial y serialización en Little-Endian
    for i in 0..16 {
        let sum = working[i].wrapping_add(state[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&sum.to_le_bytes());
    }
}

/// Aplica el cifrado/descifrado de flujo ChaCha20 sobre un búfer de datos in-place (XOR).
pub fn chacha20_xor(key: &[u8; 32], initial_counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut block = [0u8; 64];
    let mut counter = initial_counter;

    for chunk in data.chunks_mut(64) {
        chacha20_block(key, counter, nonce, &mut block);
        let chunk_len = chunk.len();
        for (d, k) in chunk.iter_mut().zip(&block[..chunk_len]) {
            *d ^= *k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Deriva determinísticamente una clave ChaCha20 de 256 bits (32 bytes) a partir de una PSK.
///
/// Si la PSK es de 16 bytes (128 bits), se expande a 32 bytes de forma determinista
/// combinando la clave y su complemento XOR con constantes de dominio de Capa 8.
/// Si la PSK es de 32 bytes (256 bits), se utiliza directamente.
pub fn derive_chacha20_key(psk: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    if psk.len() >= 32 {
        key.copy_from_slice(&psk[0..32]);
    } else if psk.len() == 16 {
        key[0..16].copy_from_slice(psk);
        // Expansión con máscara de dominio de Capa 8 para los 16 bytes superiores
        const DOMAIN_MASK: [u8; 16] = [
            0x49, 0x4c, 0x50, 0x2d, 0x4c, 0x38, 0x2d, 0x43, // "ILP-L8-C"
            0x48, 0x41, 0x43, 0x48, 0x41, 0x32, 0x30, 0x21, // "HACHA20!"
        ];
        for i in 0..16 {
            key[16 + i] = psk[i] ^ DOMAIN_MASK[i];
        }
    } else {
        // Pad simple si la clave tiene otra longitud
        let copy_len = psk.len().min(32);
        key[0..copy_len].copy_from_slice(&psk[0..copy_len]);
    }
    key
}

/// Construye un nonce estándar de 96 bits (12 bytes) para una trama I-PDU de Capa 8.
///
/// **Separación de Dominios Criptográficos:**
/// - Peticiones (Sidecar -> Gateway): `session_uuid` directo en los primeros 8 bytes.
/// - Respuestas (Gateway -> Sidecar): `session_uuid ^ 0x8000_0000_0000_0000` en los primeros 8 bytes.
///   Esta inversión del bit más significativo garantiza que jamás se reutilice el mismo keystream
///   entre solicitud y respuesta cuando comparten el mismo `session_uuid`.
/// - Los últimos 4 bytes se construyen mediante `deadline_ttl_ms ^ max_budget_cap`.
pub fn derive_frame_nonce(
    session_uuid: u64,
    deadline_ttl_ms: u32,
    max_budget_cap: u32,
    is_response: bool,
) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let effective_uuid = if is_response {
        session_uuid ^ 0x8000_0000_0000_0000
    } else {
        session_uuid
    };

    nonce[0..8].copy_from_slice(&effective_uuid.to_le_bytes());
    let mix_param = deadline_ttl_ms ^ max_budget_cap;
    nonce[8..12].copy_from_slice(&mix_param.to_le_bytes());
    nonce
}

/// Cifra o descifra in-place la carga útil de una trama I-PDU mediante ChaCha20.
///
/// Dado que ChaCha20 es un cifrador de flujo simétrico, la operación de cifrado y
/// descifrado es idéntica (involución XOR).
pub fn chacha20_crypt_payload(
    psk: &[u8],
    session_uuid: u64,
    deadline_ttl_ms: u32,
    max_budget_cap: u32,
    is_response: bool,
    payload: &mut [u8],
) {
    if payload.is_empty() {
        return;
    }
    let key = derive_chacha20_key(psk);
    let nonce = derive_frame_nonce(session_uuid, deadline_ttl_ms, max_budget_cap, is_response);
    chacha20_xor(&key, 1, &nonce, payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc8439_chacha20_official_vector() {
        // Vector oficial de prueba del RFC 8439 Sección 2.3.2:
        // Key: 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let counter = 1u32;
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut out = [0u8; 64];
        chacha20_block(&key, counter, &nonce, &mut out);

        // Salida esperada oficial del RFC 8439 Sección 2.3.2:
        #[rustfmt::skip]
        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        assert_eq!(
            out, expected,
            "El bloque ChaCha20 debe coincidir exactamente con el vector oficial del RFC 8439 Sec 2.3.2"
        );
    }

    #[test]
    fn test_chacha20_roundtrip_encryption_and_decryption() {
        let psk = [0x55u8; 16];
        let session_uuid = 0x1122_3344_5566_7788u64;
        let deadline = 5000u32;
        let budget = 10000u32;

        let original = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"secure_exec\"}}";
        let mut buffer = original.to_vec();

        // 1. Cifrar
        chacha20_crypt_payload(&psk, session_uuid, deadline, budget, false, &mut buffer);
        assert_ne!(
            buffer.as_slice(),
            original.as_slice(),
            "El ciphertext debe diferir del texto plano"
        );
        assert!(
            !buffer.windows(7).any(|w| w == b"jsonrpc"),
            "El ciphertext no debe contener la cadena 'jsonrpc' en texto claro"
        );

        // 2. Descifrar con los mismos parámetros
        chacha20_crypt_payload(&psk, session_uuid, deadline, budget, false, &mut buffer);
        assert_eq!(
            buffer.as_slice(),
            original.as_slice(),
            "El descifrado debe restaurar el texto plano original"
        );
    }

    #[test]
    fn test_chacha20_domain_separation_request_vs_response() {
        let _psk = [0x77u8; 16];
        let session_uuid = 0x9999_aaaa_bbbb_ccccu64;
        let deadline = 2000u32;
        let budget = 5000u32;

        let nonce_req = derive_frame_nonce(session_uuid, deadline, budget, false);
        let nonce_resp = derive_frame_nonce(session_uuid, deadline, budget, true);

        assert_ne!(
            nonce_req, nonce_resp,
            "Los nonces de petición y respuesta deben ser disjuntos para evitar colisión de keystream"
        );
    }
}
