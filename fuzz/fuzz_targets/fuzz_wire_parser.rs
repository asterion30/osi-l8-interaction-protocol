#![no_main]

use libfuzzer_sys::fuzz_target;
use ilp_core::{IpduError, IpduPacket};
use ilp_core::ipdu::header::IpduHeader;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzzing de Cabecera Compacta (32 bytes / 256 bits)
    if let Ok(compact_hdr) = IpduHeader::from_compact_bytes(data) {
        let wire = compact_hdr.to_compact_256bit_bytes();
        let reparsed = IpduHeader::from_compact_bytes(&wire)
            .expect("Fallo de idempotencia en cabecera compacta de 32 bytes");

        // En modo compacto los primeros 28 bytes y el truncado de firma deben ser idénticos
        assert_eq!(compact_hdr.to_compact_256bit_bytes(), reparsed.to_compact_256bit_bytes());
    }

    // 2. Fuzzing de Cabecera Canónica (36 bytes)
    if let Ok(canon_hdr) = IpduHeader::from_canonical_bytes(data) {
        let wire = canon_hdr.to_canonical_bytes();
        let reparsed = IpduHeader::from_canonical_bytes(&wire)
            .expect("Fallo de idempotencia en cabecera canónica de 36 bytes");
        assert_eq!(canon_hdr, reparsed);
    }

    // 3. Fuzzing de Paquete Completo I-PDU (Cabecera + Length Prefix + Payload)
    match IpduPacket::from_bytes(data) {
        Ok(packet) => {
            // Invariante de Roundtrip: serializar y volver a parsear debe dar el mismo IpduPacket
            let wire_bytes = packet.to_bytes();
            let reparsed = IpduPacket::from_bytes(&wire_bytes)
                .expect("Invariante violada: IpduPacket válido falló al re-serializar");
            assert_eq!(packet, reparsed);
        }
        Err(
            IpduError::BufferUnderflow { .. }
            | IpduError::PayloadTooLarge(_)
            | IpduError::TruncatedPayload { .. }
            | _,
        ) => {
            // Rechazo controlado y seguro: sin panic ni OOM
        }
    }
});
