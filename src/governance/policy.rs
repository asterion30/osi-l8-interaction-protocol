//! RFC-ILP-2026: User Governance Policy Model (Sovereign Rules Engine)

use std::collections::HashSet;

/// Configuración soberana de políticas inyectadas por el usuario en el Cognitive Reference Monitor.
#[derive(Debug, Clone)]
pub struct UserGovernancePolicy {
    /// Identificador Descentralizado (DID) del usuario o entidad soberana.
    pub user_did: String,
    /// Límite máximo global de presupuesto que un agente puede asignar por intento/sesión.
    pub max_budget_cap: u32,
    /// Techo máximo de autonomía permitido en este host (ej. 3).
    pub max_autonomy_tier: u8,
    /// Límite máximo admisible para el tiempo de vida (TTL) en milisegundos.
    pub max_deadline_ms: u32,
    /// Tier a partir del cual es obligatorio exigir el flag REQUIRE_SANDBOXED_INFERENCE.
    pub require_sandbox_above_tier: u8,
    /// Prohíbe cualquier tráfico saliente hacia interfaces externas si el proceso está tintado.
    pub deny_external_egress_if_tainted: bool,
    /// Conjunto de namespaces semánticos de habilidades explícitamente bloqueadas (Blacklist).
    pub blacklisted_skills: HashSet<u64>,
    /// Lista blanca opcional de habilidades autorizadas (si está presente, solo estas pasan).
    pub whitelisted_skills: Option<HashSet<u64>>,
}

impl Default for UserGovernancePolicy {
    fn default() -> Self {
        Self {
            user_did: "did:key:z6MkhaXgBZDvotDkL5257faiz48xzpq2541".to_string(),
            max_budget_cap: 100_000,
            max_autonomy_tier: 3,
            max_deadline_ms: 60_000,
            require_sandbox_above_tier: 2,
            deny_external_egress_if_tainted: true,
            blacklisted_skills: HashSet::new(),
            whitelisted_skills: None,
        }
    }
}

impl UserGovernancePolicy {
    /// Crea una política personalizada.
    pub fn new(user_did: impl Into<String>) -> Self {
        Self {
            user_did: user_did.into(),
            ..Default::default()
        }
    }

    /// Añade una habilidad a la lista negra.
    pub fn blacklist_skill(&mut self, skill_hash: u64) {
        self.blacklisted_skills.insert(skill_hash);
    }

    /// Verifica si una habilidad está bloqueada.
    pub fn is_skill_forbidden(&self, skill_hash: u64) -> bool {
        if self.blacklisted_skills.contains(&skill_hash) {
            return true;
        }
        if let Some(ref whitelist) = self.whitelisted_skills {
            return !whitelist.contains(&skill_hash);
        }
        false
    }
}
