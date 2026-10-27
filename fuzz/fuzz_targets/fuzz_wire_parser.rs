#![no_main]

use libfuzzer_sys::fuzz_target;
use ilp_core::ipdu::header::IpduHeader;
use ilp_core::ipdu::packet::IpduPacket;

fuzz_target!(|data: &[u8]| {
    // 1. Prueba de resistencia en cabecera compacta (32 bytes / 256 bits)
    if let Ok(compact_hdr) = IpduHeader::from_compact_bytes(data) {
        let reencoded = compact_hdr.to_compact_256bit_bytes();
        let decoded_again = IpduHeader::from_compact_bytes(&reencoded)
            .expect("Invariante violada: cabecera compacta válida falló al re-parsear");
        assert_eq!(compact_hdr.version, decoded_again.version);
        assert_eq!(compact_hdr.performative, decoded_again.performative);
        assert_eq!(compact_hdr.autonomy_tier, decoded_again.autonomy_tier);
        assert_eq!(compact_hdr.policy_flags, decoded_again.policy_flags);
        assert_eq!(compact_hdr.skill_namespace_hash, decoded_again.skill_namespace_hash);
        assert_eq!(compact_hdr.session_uuid, decoded_again.session_uuid);
        assert_eq!(compact_hdr.max_budget_cap, decoded_again.max_budget_cap);
        assert_eq!(compact_hdr.deadline_ttl_ms, decoded_again.deadline_ttl_ms);
    }

    // 2. Prueba de resistencia en cabecera canónica (36 bytes / 288 bits)
    if let Ok(canon_hdr) = IpduHeader::from_canonical_bytes(data) {
        let reencoded = canon_hdr.to_canonical_bytes();
        let decoded_again = IpduHeader::from_canonical_bytes(&reencoded)
            .expect("Invariante violada: cabecera canónica válida falló al re-parsear");
        assert_eq!(canon_hdr, decoded_again);
    }

    // 3. Prueba de resistencia en paquete I-PDU completo (Cabecera + Length + Payload con blindaje de cotas)
    if let Ok(packet) = IpduPacket::from_bytes(data) {
        let wire_bytes = packet.to_bytes();
        let roundtrip = IpduPacket::from_bytes(&wire_bytes)
            .expect("Invariante violada: paquete I-PDU válido falló en roundtrip");
        assert_eq!(packet.header, roundtrip.header);
        assert_eq!(packet.payload, roundtrip.payload);
    }
});
