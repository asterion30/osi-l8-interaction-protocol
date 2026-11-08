//! RFC-ILP-2026: User Governance Policy Model (Sovereign Rules Engine)
//!
//! Proporciona carga declarativa de políticas desde archivos de configuración tipo `.conf`
//! de sistemas UNIX sin dependencias externas (Zero-Deps Parser).

use std::collections::HashSet;
use std::fmt;

/// Error ocurrido al parsear un archivo de configuración de gobernanza `.conf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyParseError {
    pub line_number: usize,
    pub message: String,
}

impl fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Error de política en línea {}: {}",
            self.line_number, self.message
        )
    }
}

impl std::error::Error for PolicyParseError {}

/// Configuración soberana de políticas inyectadas por el usuario en el Cognitive Reference Monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Parsea un u64 aceptando notación decimal ("12345") o hexadecimal ("0xDEADBEEF").
    fn parse_u64_token(val: &str) -> Result<u64, String> {
        let trimmed = val.trim();
        if let Some(hex_str) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            u64::from_str_radix(hex_str, 16)
                .map_err(|e| format!("Valor hexadecimal inválido '{}': {}", val, e))
        } else {
            trimmed
                .parse::<u64>()
                .map_err(|e| format!("Valor numérico u64 inválido '{}': {}", val, e))
        }
    }

    /// Parsea un booleano aceptando true/false/1/0/yes/no.
    fn parse_bool_token(val: &str) -> Result<bool, String> {
        match val.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(format!("Valor booleano inválido '{}'", val)),
        }
    }

    /// Carga una política desde un string en formato de configuración `.conf` estricto UNIX.
    pub fn from_conf_str(conf: &str) -> Result<Self, PolicyParseError> {
        let mut policy = Self::default();
        let mut seen_keys = HashSet::new();

        for (idx, raw_line) in conf.lines().enumerate() {
            let line_number = idx + 1;
            let line = raw_line.trim();

            // Ignorar líneas vacías o comentarios (# o //)
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            // Partir en clave = valor
            let (key, value) = line.split_once('=').ok_or_else(|| PolicyParseError {
                line_number,
                message: format!(
                    "Sintaxis inválida (se esperaba 'clave = valor'): '{}'",
                    line
                ),
            })?;

            let key = key.trim();
            let value = value.trim();

            if key.is_empty() {
                return Err(PolicyParseError {
                    line_number,
                    message: "Clave vacía en directiva de configuración".to_string(),
                });
            }

            if key != "blacklist_skill" && key != "whitelist_skill" && !seen_keys.insert(key) {
                return Err(PolicyParseError {
                    line_number,
                    message: format!("Clave duplicada no permitida: '{}'", key),
                });
            }

            match key {
                "user_did" => {
                    policy.user_did = value.to_string();
                }
                "max_budget_cap" => {
                    let parsed = value.parse::<u32>().map_err(|e| PolicyParseError {
                        line_number,
                        message: format!("max_budget_cap inválido: {}", e),
                    })?;
                    policy.max_budget_cap = parsed;
                }
                "max_autonomy_tier" => {
                    let parsed = value.parse::<u8>().map_err(|e| PolicyParseError {
                        line_number,
                        message: format!("max_autonomy_tier inválido: {}", e),
                    })?;
                    if parsed > 63 {
                        return Err(PolicyParseError {
                            line_number,
                            message: format!(
                                "max_autonomy_tier excede el límite de 63: {}",
                                parsed
                            ),
                        });
                    }
                    policy.max_autonomy_tier = parsed;
                }
                "max_deadline_ms" => {
                    let parsed = value.parse::<u32>().map_err(|e| PolicyParseError {
                        line_number,
                        message: format!("max_deadline_ms inválido: {}", e),
                    })?;
                    policy.max_deadline_ms = parsed;
                }
                "require_sandbox_above_tier" => {
                    let parsed = value.parse::<u8>().map_err(|e| PolicyParseError {
                        line_number,
                        message: format!("require_sandbox_above_tier inválido: {}", e),
                    })?;
                    if parsed > 63 {
                        return Err(PolicyParseError {
                            line_number,
                            message: format!(
                                "require_sandbox_above_tier excede el límite de 63: {}",
                                parsed
                            ),
                        });
                    }
                    policy.require_sandbox_above_tier = parsed;
                }
                "deny_external_egress_if_tainted" => {
                    let parsed = Self::parse_bool_token(value).map_err(|msg| PolicyParseError {
                        line_number,
                        message: msg,
                    })?;
                    policy.deny_external_egress_if_tainted = parsed;
                }
                "blacklist_skill" => {
                    let hash = Self::parse_u64_token(value).map_err(|msg| PolicyParseError {
                        line_number,
                        message: msg,
                    })?;
                    policy.blacklisted_skills.insert(hash);
                }
                "whitelist_skill" => {
                    let hash = Self::parse_u64_token(value).map_err(|msg| PolicyParseError {
                        line_number,
                        message: msg,
                    })?;
                    let set = policy.whitelisted_skills.get_or_insert_with(HashSet::new);
                    set.insert(hash);
                }
                unknown => {
                    return Err(PolicyParseError {
                        line_number,
                        message: format!("Directiva desconocida: '{}'", unknown),
                    });
                }
            }
        }

        Ok(policy)
    }

    /// Serializa la política actual a un formato textual `.conf` canónico.
    pub fn to_conf_string(&self) -> String {
        let mut out = String::new();
        out.push_str("# RFC-ILP-2026: User Governance Policy Configuration\n");
        out.push_str(&format!("user_did = {}\n", self.user_did));
        out.push_str(&format!("max_budget_cap = {}\n", self.max_budget_cap));
        out.push_str(&format!("max_autonomy_tier = {}\n", self.max_autonomy_tier));
        out.push_str(&format!("max_deadline_ms = {}\n", self.max_deadline_ms));
        out.push_str(&format!(
            "require_sandbox_above_tier = {}\n",
            self.require_sandbox_above_tier
        ));
        out.push_str(&format!(
            "deny_external_egress_if_tainted = {}\n",
            self.deny_external_egress_if_tainted
        ));

        let mut sorted_blacklist: Vec<_> = self.blacklisted_skills.iter().copied().collect();
        sorted_blacklist.sort_unstable();
        for hash in sorted_blacklist {
            out.push_str(&format!("blacklist_skill = 0x{:016X}\n", hash));
        }

        if let Some(ref whitelist) = self.whitelisted_skills {
            let mut sorted_whitelist: Vec<_> = whitelist.iter().copied().collect();
            sorted_whitelist.sort_unstable();
            for hash in sorted_whitelist {
                out.push_str(&format!("whitelist_skill = 0x{:016X}\n", hash));
            }
        }

        out
    }
}
