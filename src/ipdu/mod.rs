//! RFC-ILP-2026: Interaction Protocol Data Unit (I-PDU) Module

pub mod flags;
pub mod header;
pub mod packet;
pub mod performatives;

pub use flags::CognitivePolicyFlags;
pub use header::{
    IpduError, IpduHeader, CANONICAL_HEADER_SIZE, COMPACT_256BIT_HEADER_SIZE, ILP_VERSION_1,
};
pub use packet::{validate_frame_bounds, IpduPacket, MAX_ILP_PAYLOAD_SIZE};
pub use performatives::{Performative, PerformativeError};
