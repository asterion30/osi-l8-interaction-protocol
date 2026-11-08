//! RFC-ILP-2026: Layer 8 Governance and Cognitive Reference Monitor Module

pub mod firewall;
pub mod gatekeeper;
pub mod policy;
pub mod taint;

pub use firewall::{
    AuditRecord, CognitiveErrorCode, CognitiveFirewall, FilterDecision, Verdict,
    DEFAULT_MAX_AUDIT_LOG_CAPACITY,
};
#[allow(deprecated)]
pub use gatekeeper::SlmGatekeeper;
pub use gatekeeper::{GatekeeperThreat, HeuristicGatekeeper};
pub use policy::{PolicyParseError, UserGovernancePolicy};
pub use taint::{ProcessTaintContext, TaintEvent, TaintTag};
