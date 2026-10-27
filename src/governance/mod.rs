//! RFC-ILP-2026: Layer 8 Governance and Cognitive Reference Monitor Module

pub mod firewall;
pub mod gatekeeper;
pub mod policy;
pub mod taint;

pub use firewall::{AuditRecord, CognitiveErrorCode, CognitiveFirewall, FilterDecision, Verdict};
pub use gatekeeper::{GatekeeperThreat, SlmGatekeeper};
pub use policy::UserGovernancePolicy;
pub use taint::{ProcessTaintContext, TaintTag};
