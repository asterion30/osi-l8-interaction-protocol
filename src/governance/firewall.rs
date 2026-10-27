//! RFC-ILP-2026: Cognitive Reference Monitor (CRM) & Mandatory Semantic Access Control (MSAC) Firewall

use crate::ipdu::flags::CognitivePolicyFlags;
use crate::ipdu::packet::IpduPacket;
use crate::governance::gatekeeper::{GatekeeperThreat, SlmGatekeeper};
use crate::governance::policy::UserGovernancePolicy;
use crate::governance::taint::{ProcessTaintContext, TaintTag};
use std::collections::VecDeque;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Códigos de error de denegación de acceso semántico en el kernel (equivalentes a errno POSIX).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CognitiveErrorCode {
    /// -EPERM_COGNITIVE_POLICY: Violación de la política cognitiva del usuario por tinte de proceso o DLP.
    EpermCognitivePolicy,
    /// -EPERM_AUTONOMY_EXCEEDED: El agente intentó una autonomía superior al techo soberano concedido.
    EpermAutonomyExceeded,
    /// -EPERM_BUDGET_EXCEEDED: El presupuesto declarado supera el límite máximo autorizado por el usuario.
    EpermBudgetExceeded,
    /// -EPERM_INVALID_DEADLINE: El tiempo de expiración TTL es nulo o supera el límite permitido.
    EpermInvalidDeadline,
    /// -EPERM_FORBIDDEN_SKILL: La habilidad solicitada u ofrecida se encuentra en la lista negra del usuario.
    EpermForbiddenSkill,
    /// -EPERM_SANDBOX_REQUIRED: La acción requiere ejecución en sandbox pero el flag no fue especificado.
    EpermSandboxRequired,
    /// -EPERM_SEMANTIC_EXFILTRATION: El guardián SLM detectó exfiltración semántica de datos sensibles.
    EpermSemanticExfiltration,
    /// -EPERM_PROMPT_INJECTION: Intento de inyección adversaria o subversión de políticas detectada.
    EpermPromptInjection,
}

impl fmt::Display for CognitiveErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpermCognitivePolicy => write!(f, "EPERM_COGNITIVE_POLICY (Kernel Drop)"),
            Self::EpermAutonomyExceeded => write!(f, "EPERM_AUTONOMY_EXCEEDED (Techo de autonomía violado)"),
            Self::EpermBudgetExceeded => write!(f, "EPERM_BUDGET_EXCEEDED (Límite presupuestario superado)"),
            Self::EpermInvalidDeadline => write!(f, "EPERM_INVALID_DEADLINE (TTL fuera de límites)"),
            Self::EpermForbiddenSkill => write!(f, "EPERM_FORBIDDEN_SKILL (Habilidad no autorizada)"),
            Self::EpermSandboxRequired => write!(f, "EPERM_SANDBOX_REQUIRED (Requiere flag REQUIRE_SANDBOXED_INFERENCE)"),
            Self::EpermSemanticExfiltration => write!(f, "EPERM_SEMANTIC_EXFILTRATION (Fuga detectada por SLM)"),
            Self::EpermPromptInjection => write!(f, "EPERM_PROMPT_INJECTION (Intento de evasión adversarial)"),
        }
    }
}

/// Veredicto formal emitido por el Firewall Cognitivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Paquete aprobado: cumple todas las restricciones de gobernanza y puede transmitirse a Capa 6 (TLS).
    Allow,
    /// Paquete descartado atómicamente a nivel de kernel/demonio sin salir a la red.
    Drop,
}

/// Registro estructurado de auditoría forense para eventos de seguridad cognitiva.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub timestamp_ms: u64,
    pub session_uuid: u64,
    pub pid: u32,
    pub agent_name: String,
    pub performative: String,
    pub verdict: Verdict,
    pub error_code: Option<CognitiveErrorCode>,
    pub reason: String,
    pub step_failed: Option<u8>,
}

/// Decisión resultante del análisis del filtro MSAC.
#[derive(Debug, Clone)]
pub struct FilterDecision {
    pub verdict: Verdict,
    pub error_code: Option<CognitiveErrorCode>,
    pub reason: Option<String>,
    pub step_failed: Option<u8>,
    pub audit_record: AuditRecord,
}

impl FilterDecision {
    pub fn is_allowed(&self) -> bool {
        self.verdict == Verdict::Allow
    }
}

/// Capacidad máxima por defecto del registro de auditoría en memoria (Ring Buffer).
pub const DEFAULT_MAX_AUDIT_LOG_CAPACITY: usize = 10_000;

/// Cognitive Reference Monitor (CRM): El Firewall Cognitivo de Capa 8.
#[derive(Debug, Clone)]
pub struct CognitiveFirewall {
    pub policy: UserGovernancePolicy,
    pub gatekeeper: SlmGatekeeper,
    pub audit_log: VecDeque<AuditRecord>,
    pub max_audit_entries: usize,
}

impl CognitiveFirewall {
    /// Instancia un nuevo firewall cognitivo con la política soberana de usuario y Ring Buffer acotado.
    pub fn new(policy: UserGovernancePolicy) -> Self {
        Self::with_audit_capacity(policy, DEFAULT_MAX_AUDIT_LOG_CAPACITY)
    }

    /// Instancia un firewall cognitivo con capacidad máxima configurable en su Ring Buffer de auditoría.
    /// Si `max_audit_entries` es 0, el registro almacena eventos sin límite superior (modo desaconsejado en producción).
    pub fn with_audit_capacity(policy: UserGovernancePolicy, max_audit_entries: usize) -> Self {
        Self {
            policy,
            gatekeeper: SlmGatekeeper::new(),
            audit_log: VecDeque::new(),
            max_audit_entries,
        }
    }

    /// Registra un evento en el log de auditoría respetando la cota de Ring Buffer (FIFO).
    #[inline]
    fn push_audit_record(&mut self, record: AuditRecord) {
        if self.max_audit_entries > 0 && self.audit_log.len() >= self.max_audit_entries {
            self.audit_log.pop_front();
        }
        self.audit_log.push_back(record);
    }

    /// Intercepta y audita atómicamente la emisión de un I-PDU en 3 pasos obligatorios (MSAC).
    pub fn inspect_egress(
        &mut self,
        process: &ProcessTaintContext,
        packet: &IpduPacket,
    ) -> FilterDecision {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let session_uuid = packet.header.session_uuid;
        let perf_str = packet.header.performative.to_string();

        // =========================================================================
        // PASO 1: Auditoría de Tinte de Proceso vs Políticas de Privacidad (Sub-microsegundo)
        // =========================================================================
        if process.is_external_egress && self.policy.deny_external_egress_if_tainted {
            let critical_taint = TaintTag::MEDICAL_PII
                | TaintTag::FINANCIAL_DATA
                | TaintTag::CREDENTIALS
                | TaintTag::GOVERNMENT_ID;

            if process.has_taint(critical_taint) {
                let reason = format!(
                    "Bloqueo MSAC: Proceso PID {} ({}) tiene tinte [{}] y prohíbe salida a red externa",
                    process.pid, process.agent_name, process.taint
                );

                let record = AuditRecord {
                    timestamp_ms: now_ms,
                    session_uuid,
                    pid: process.pid,
                    agent_name: process.agent_name.clone(),
                    performative: perf_str,
                    verdict: Verdict::Drop,
                    error_code: Some(CognitiveErrorCode::EpermCognitivePolicy),
                    reason: reason.clone(),
                    step_failed: Some(1),
                };
                self.push_audit_record(record.clone());

                return FilterDecision {
                    verdict: Verdict::Drop,
                    error_code: Some(CognitiveErrorCode::EpermCognitivePolicy),
                    reason: Some(reason),
                    step_failed: Some(1),
                    audit_record: record,
                };
            }
        }

        // =========================================================================
        // PASO 2: Evaluación Determinista de Cabecera Binaria y Reglas del Usuario (O(1))
        // =========================================================================
        let header = &packet.header;

        // 2.1 Límite de autonomía concedida
        if header.autonomy_tier > self.policy.max_autonomy_tier {
            let reason = format!(
                "Autonomy Tier {} excede el techo máximo autorizado por el usuario ({})",
                header.autonomy_tier, self.policy.max_autonomy_tier
            );
            return self.record_drop(
                now_ms,
                session_uuid,
                process,
                perf_str,
                CognitiveErrorCode::EpermAutonomyExceeded,
                reason,
                2,
            );
        }

        // 2.2 Requisito de Sandbox en altas autonomías
        if header.autonomy_tier >= self.policy.require_sandbox_above_tier
            && !header
                .policy_flags
                .contains(CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE)
        {
            let reason = format!(
                "Autonomy Tier {} requiere obligatoriamente flag REQUIRE_SANDBOXED_INFERENCE",
                header.autonomy_tier
            );
            return self.record_drop(
                now_ms,
                session_uuid,
                process,
                perf_str,
                CognitiveErrorCode::EpermSandboxRequired,
                reason,
                2,
            );
        }

        // 2.3 Límite presupuestario (Max Budget Cap)
        if header.max_budget_cap > self.policy.max_budget_cap {
            let reason = format!(
                "Presupuesto declarado ({}) supera el tope soberano ({})",
                header.max_budget_cap, self.policy.max_budget_cap
            );
            return self.record_drop(
                now_ms,
                session_uuid,
                process,
                perf_str,
                CognitiveErrorCode::EpermBudgetExceeded,
                reason,
                2,
            );
        }

        // 2.4 Control de expiración / Deadlines (TTL)
        if header.deadline_ttl_ms == 0 || header.deadline_ttl_ms > self.policy.max_deadline_ms {
            let reason = format!(
                "Deadline TTL {} ms fuera del rango permitido (1..{} ms)",
                header.deadline_ttl_ms, self.policy.max_deadline_ms
            );
            return self.record_drop(
                now_ms,
                session_uuid,
                process,
                perf_str,
                CognitiveErrorCode::EpermInvalidDeadline,
                reason,
                2,
            );
        }

        // 2.5 Lista de control de acceso para Skills (Blacklist)
        if self.policy.is_skill_forbidden(header.skill_namespace_hash) {
            let reason = format!(
                "Habilidad con namespace hash {:#018x} bloqueada en política de usuario",
                header.skill_namespace_hash
            );
            return self.record_drop(
                now_ms,
                session_uuid,
                process,
                perf_str,
                CognitiveErrorCode::EpermForbiddenSkill,
                reason,
                2,
            );
        }

        // =========================================================================
        // PASO 3: Guardián SLM Embebido: Inspección Profunda de Carga Útil (<5 ms)
        // =========================================================================
        if let Err(threat) = self.gatekeeper.inspect(&packet.payload) {
            let (err_code, reason) = match threat {
                GatekeeperThreat::FinancialExfiltration(msg) => {
                    (CognitiveErrorCode::EpermSemanticExfiltration, msg)
                }
                GatekeeperThreat::CredentialLeak(msg) => {
                    (CognitiveErrorCode::EpermSemanticExfiltration, msg)
                }
                GatekeeperThreat::GovernmentIdLeak(msg) => {
                    (CognitiveErrorCode::EpermSemanticExfiltration, msg)
                }
                GatekeeperThreat::PromptInjectionAttempt(msg) => {
                    (CognitiveErrorCode::EpermPromptInjection, msg)
                }
            };

            return self.record_drop(
                now_ms,
                session_uuid,
                process,
                perf_str,
                err_code,
                format!("Guardián SLM bloqueó el paquete: {}", reason),
                3,
            );
        }

        // =========================================================================
        // VEREDICTO FINAL: AUTORIZADO (Pasa a Capa 6 Cifrado TLS y NIC)
        // =========================================================================
        let record = AuditRecord {
            timestamp_ms: now_ms,
            session_uuid,
            pid: process.pid,
            agent_name: process.agent_name.clone(),
            performative: perf_str,
            verdict: Verdict::Allow,
            error_code: None,
            reason: "Verificación MSAC completada con éxito. Políticas conformes.".into(),
            step_failed: None,
        };
        self.push_audit_record(record.clone());

        FilterDecision {
            verdict: Verdict::Allow,
            error_code: None,
            reason: None,
            step_failed: None,
            audit_record: record,
        }
    }

    fn record_drop(
        &mut self,
        now_ms: u64,
        session_uuid: u64,
        process: &ProcessTaintContext,
        perf_str: String,
        error_code: CognitiveErrorCode,
        reason: String,
        step: u8,
    ) -> FilterDecision {
        let record = AuditRecord {
            timestamp_ms: now_ms,
            session_uuid,
            pid: process.pid,
            agent_name: process.agent_name.clone(),
            performative: perf_str,
            verdict: Verdict::Drop,
            error_code: Some(error_code),
            reason: reason.clone(),
            step_failed: Some(step),
        };
        self.push_audit_record(record.clone());

        FilterDecision {
            verdict: Verdict::Drop,
            error_code: Some(error_code),
            reason: Some(reason),
            step_failed: Some(step),
            audit_record: record,
        }
    }
}
