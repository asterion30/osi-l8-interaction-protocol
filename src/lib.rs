//! # ILP-Core: Reference Prototype for OSI Layer 8 Interaction Protocol (RFC-ILP-2026)
//!
//! Este crate implementa la especificación formal de la **Capa 8 de Interacción Semántica
//! y Gobernanza Agéntica (ILP / ISO-7498-8 Draft)**, compuesta por:
//!
//! 1. **Módulo `ipdu`**: Cabecera binaria de 256 bits (32/36 bytes) de la I-PDU,
//!    empaquetado de actos de habla (Speech Acts), bitflags cognitivas y serialización en Network Byte Order.
//! 2. **Módulo `governance`**: Cognitive Reference Monitor (CRM) y mecanismo
//!    Mandatory Semantic Access Control (MSAC) con Taint Tracking, reglas declarativas y SLM Gatekeeper.

pub mod governance;
pub mod ipdu;

// Re-exportaciones principales
pub use governance::{
    AuditRecord, CognitiveErrorCode, CognitiveFirewall, FilterDecision, ProcessTaintContext,
    TaintTag, UserGovernancePolicy, Verdict,
};
pub use ipdu::{
    validate_frame_bounds, CognitivePolicyFlags, IpduError, IpduHeader, IpduPacket, Performative,
    CANONICAL_HEADER_SIZE, COMPACT_256BIT_HEADER_SIZE, ILP_VERSION_1, MAX_ILP_PAYLOAD_SIZE,
};
