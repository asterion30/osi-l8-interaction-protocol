//! RFC-ILP-2026: I-PDU Frame MAC Authentication (SipHash-2-4)
//!
//! Proporciona autenticación criptográfica e integridad de trama en espacio de usuario
//! y kernel utilizando una clave pre-compartida (PSK) de 128 bits sin dependencias externas.

use super::header::IpduHeader;

/// Implementación canónica determinista de SipHash-2-4 de 64 bits
/// ("SipHash: a fast short-input PRF", Jean-Philippe Aumasson & Daniel J. Bernstein, INDOCRYPT 2012)
/// en Rust estándar.
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
        for (i, &byte) in self.buffer.iter().take(self.buf_len).enumerate() {
            b |= (byte as u64) << (8 * i);
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

/// Parsea una cadena hexadecimal de 32 caracteres (128 bits) a `[u8; 16]`.
pub fn parse_hex_psk(hex_str: &str) -> Result<[u8; 16], String> {
    let trimmed = hex_str
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if trimmed.len() != 32 {
        return Err(format!(
            "La clave PSK debe contener exactamente 32 dígitos hexadecimales (128 bits), se recibieron {}",
            trimmed.len()
        ));
    }
    let mut key = [0u8; 16];
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        key[i] = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("Valor hexadecimal inválido '{}': {}", pair, e))?;
    }
    Ok(key)
}

/// Carga una clave pre-compartida (PSK) de 128 bits desde un archivo de forma segura y libre de TOCTOU.
///
/// Garantías de seguridad:
/// 1. Rechaza enlaces simbólicos (symlinks) usando `symlink_metadata` antes de abrir.
/// 2. Abre el descriptor de archivo una sola vez (`File::open`).
/// 3. Valida en el descriptor abierto (`fstat` vía `file.metadata()?`) que sea un archivo regular
///    y que en plataformas Unix no tenga permisos para grupo ni otros (`mode & 0o077 == 0`).
/// 4. Acota la lectura a un máximo de 256 bytes (`file.take(256).read_to_string`) para mitigar DoS.
pub fn load_psk_from_file_secure(path: &str) -> Result<[u8; 16], String> {
    use std::io::Read;

    // 1. Detección explícita de symlink
    let sym_meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("No se pudo inspeccionar el archivo PSK '{}': {}", path, e))?;
    if sym_meta.file_type().is_symlink() {
        return Err("Security error: --psk-file must not be a symbolic link".to_string());
    }

    // 2. Apertura única del descriptor
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("No se pudo abrir el archivo PSK '{}': {}", path, e))?;

    // 3. Inspección sobre el descriptor abierto (fstat) libre de TOCTOU
    let meta = file.metadata().map_err(|e| {
        format!(
            "No se pudo obtener metadata del archivo PSK abierto '{}': {}",
            path, e
        )
    })?;

    if !meta.is_file() {
        return Err(format!("'{}' no es un archivo regular", path));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "Permisos inseguros en archivo PSK '{}' (modo {:o}): debe ser accesible solo por el propietario (chmod 600 o 400)",
                path, mode
            ));
        }
    }

    // 4. Lectura acotada a 256 bytes
    let mut content = String::new();
    (&mut file)
        .take(256)
        .read_to_string(&mut content)
        .map_err(|e| format!("Error al leer archivo PSK '{}': {}", path, e))?;

    parse_hex_psk(&content)
}

/// Verifica el MAC de integridad de una trama I-PDU comparando byte a byte en tiempo constante
/// mitigado con barrera de optimización del compilador (`black_box`).
///
/// **Alcance Criptográfico del Tag de 64 bits**:
/// SipHash-2-4 produce un tag de autenticación de 64 bits. Para tráfico de red a alta velocidad,
/// una colisión accidental o de falsificación ciega tiene una probabilidad de 2^-64 por intento,
/// lo cual es suficiente para integridad de trama punto a punto. La comparación se realiza sobre
/// los 8 bytes independientes acumulando un XOR en tiempo constante para mitigar ataques de canal
/// lateral (timing side-channels).
pub fn verify_frame_mac(
    header: &IpduHeader,
    payload: &[u8],
    secret_key: &[u8; 16],
    expected_mac: u64,
) -> bool {
    let computed_mac = compute_frame_mac(header, payload, secret_key);
    let a = computed_mac.to_le_bytes();
    let b = expected_mac.to_le_bytes();
    let mut diff: u8 = 0;
    for i in 0..8 {
        diff |= std::hint::black_box(a[i] ^ b[i]);
    }
    std::hint::black_box(diff) == 0
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

    #[test]
    fn test_siphash24_official_paper_vectors() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        // 1. Vector oficial para input vacío (0 bytes) -> 0x726fdb47dd0e0e31
        let mut hasher0 = SipHash24::new_with_key(&key);
        hasher0.update(&[]);
        assert_eq!(hasher0.finish(), 0x726fdb47dd0e0e31);

        // 2. Vector oficial para 1 byte [0x00] -> 0x74f839c593dc67fd
        let mut hasher1 = SipHash24::new_with_key(&key);
        hasher1.update(&[0x00]);
        assert_eq!(hasher1.finish(), 0x74f839c593dc67fd);

        // 3. Vector oficial para bytes 0..14 [0x00..=0x0e] (15 bytes) -> 0xa129ca6149be45e5
        let in15: Vec<u8> = (0..=14).collect();
        let mut hasher15 = SipHash24::new_with_key(&key);
        hasher15.update(&in15);
        assert_eq!(hasher15.finish(), 0xa129ca6149be45e5);
    }
}
