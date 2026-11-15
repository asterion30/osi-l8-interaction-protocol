//! RFC-ILP-2026: Interaction Protocol Data Unit (I-PDU) Module

pub mod auth;
pub mod crypto;
pub mod flags;
pub mod header;
pub mod packet;
pub mod performatives;

pub use auth::{
    compute_frame_mac, generate_cryptographic_session_uuid, load_psk_from_file_secure,
    parse_hex_psk, verify_frame_mac,
};
pub use crypto::{
    chacha20_block, chacha20_crypt_payload, chacha20_xor, derive_chacha20_key, derive_frame_nonce,
};
pub use flags::CognitivePolicyFlags;
pub use header::{
    IpduError, IpduHeader, CANONICAL_HEADER_SIZE, COMPACT_256BIT_HEADER_SIZE, ILP_VERSION_1,
};
pub use packet::{validate_frame_bounds, IpduPacket, MAX_ILP_PAYLOAD_SIZE};
pub use performatives::{Performative, PerformativeError};
