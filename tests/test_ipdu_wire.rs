//! Integration tests for I-PDU wire format and binary serialization

use ilp_core::ipdu::{
    CognitivePolicyFlags, IpduError, IpduHeader, IpduPacket, Performative, CANONICAL_HEADER_SIZE,
    COMPACT_256BIT_HEADER_SIZE, ILP_VERSION_1,
};

#[test]
fn test_word0_packing_and_unpacking() {
    let version = ILP_VERSION_1;
    let performative = Performative::ProposeIntent;
    let autonomy_tier = 42; // 6 bits (0..63)
    let flags = CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE
        | CognitivePolicyFlags::DENY_EGRESS_FINANCIAL;

    let header = IpduHeader::new(
        performative,
        autonomy_tier,
        flags,
        0x1122_3344_5566_7788,
        0x8877_6655_4433_2211,
        5000,
        10000,
        0xDEAD_BEEF_CAFE_BABE,
    )
    .expect("Valid header creation");

    let packed_word0 = header.pack_word0();

    let (dec_v, dec_p, dec_t, dec_f) =
        IpduHeader::unpack_word0(packed_word0).expect("Successful word0 unpack");

    assert_eq!(dec_v, version);
    assert_eq!(dec_p, performative);
    assert_eq!(dec_t, autonomy_tier);
    assert_eq!(dec_f, flags);
}

#[test]
fn test_canonical_header_roundtrip() {
    let header = IpduHeader::new(
        Performative::CommitContract,
        3,
        CognitivePolicyFlags::ALLOW_DELEGATION | CognitivePolicyFlags::ENCRYPTED_PAYLOAD,
        0xABCD_EF01_2345_6789,
        0x9876_5432_10FE_DCBA,
        75_000,
        25_000,
        0xAABB_CCDD_EEFF_0011,
    )
    .unwrap();

    let bytes = header.to_canonical_bytes();
    assert_eq!(bytes.len(), CANONICAL_HEADER_SIZE);
    assert_eq!(bytes.len(), 36);

    let decoded = IpduHeader::from_canonical_bytes(&bytes).expect("Valid header unpack");
    assert_eq!(header, decoded);
}

#[test]
fn test_compact_256bit_header_roundtrip() {
    let header = IpduHeader::new(
        Performative::DiscoverSkill,
        0,
        CognitivePolicyFlags::EMPTY,
        0x1234_5678_9ABC_DEF0,
        0x0FED_CBA9_8765_4321,
        1000,
        5000,
        0x1122_3344_0000_0000, // Upper 32 bits populated
    )
    .unwrap();

    let bytes = header.to_compact_256bit_bytes();
    assert_eq!(bytes.len(), COMPACT_256BIT_HEADER_SIZE);
    assert_eq!(bytes.len(), 32);

    let decoded = IpduHeader::from_compact_bytes(&bytes).expect("Valid compact unpack");
    assert_eq!(decoded.version, ILP_VERSION_1);
    assert_eq!(decoded.performative, Performative::DiscoverSkill);
    assert_eq!(decoded.user_rule_sig_hash, 0x1122_3344_0000_0000);
}

#[test]
fn test_complete_packet_roundtrip() {
    let payload = b"{\"intent\": \"convert_cad_to_gcode\", \"precision_mm\": 0.05}".to_vec();

    let header = IpduHeader::new(
        Performative::ProposeIntent,
        2,
        CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE,
        0x5555_6666_7777_8888,
        0x1111_2222_3333_4444,
        20_000,
        8_000,
        0x9999_AAAA_BBBB_CCCC,
    )
    .unwrap();

    let packet = IpduPacket::new(header, payload.clone());
    let wire = packet.to_bytes();

    assert_eq!(wire.len(), CANONICAL_HEADER_SIZE + 4 + payload.len());

    let decoded = IpduPacket::from_bytes(&wire).expect("Successful wire unpack");
    assert_eq!(packet, decoded);
    assert_eq!(decoded.payload_as_str().unwrap(), "{\"intent\": \"convert_cad_to_gcode\", \"precision_mm\": 0.05}");
}

#[test]
fn test_unsupported_version_error() {
    let mut bytes = [0u8; CANONICAL_HEADER_SIZE];
    // Word 0 with Version 2 (0x2 << 28)
    let bad_word0 = 0x2000_0000u32;
    bytes[0..4].copy_from_slice(&bad_word0.to_be_bytes());

    let res = IpduHeader::from_canonical_bytes(&bytes);
    match res {
        Err(IpduError::UnsupportedVersion(v)) => assert_eq!(v, 2),
        other => panic!("Expected UnsupportedVersion, got {:?}", other),
    }
}

#[test]
fn test_buffer_underflow_error() {
    let tiny_buf = [0u8; 10];
    let res = IpduHeader::from_canonical_bytes(&tiny_buf);
    assert!(matches!(res, Err(IpduError::BufferUnderflow { .. })));
}
