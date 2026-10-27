#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ilp_core::governance::firewall::{CognitiveFirewall, Verdict};
use ilp_core::governance::policy::UserGovernancePolicy;
use ilp_core::governance::taint::{ProcessTaintContext, TaintTag};
use ilp_core::ipdu::flags::CognitivePolicyFlags;
use ilp_core::ipdu::header::IpduHeader;
use ilp_core::ipdu::packet::IpduPacket;
use ilp_core::ipdu::performatives::Performative;

#[derive(Arbitrary, Debug)]
struct FuzzMsacScenario {
    perf_idx: u8,
    autonomy_tier: u8,
    raw_flags: u16,
    skill_hash: u64,
    session_uuid: u64,
    budget_cap: u32,
    ttl_ms: u32,
    sig_hash: u64,
    payload: Vec<u8>,
    is_medical_tainted: bool,
    is_financial_tainted: bool,
    policy_max_budget: u32,
    forbidden_skill: u64,
}

fuzz_target!(|scenario: FuzzMsacScenario| {
    // Mapeo determinista de entradas difusas a tipos válidos de protocolo
    let performative = match scenario.perf_idx % 6 {
        0 => Performative::DiscoverSkill,
        1 => Performative::ProposeIntent,
        2 => Performative::CounterOffer,
        3 => Performative::CommitContract,
        4 => Performative::RejectPolicy,
        _ => Performative::AttestResult,
    };

    let policy_flags = CognitivePolicyFlags::from_bits_truncate(scenario.raw_flags);
    let tier = scenario.autonomy_tier & 0x3F; // Máscara de 6 bits (0..63)

    let header = IpduHeader {
        version: 0x1,
        performative,
        autonomy_tier: tier,
        policy_flags,
        skill_namespace_hash: scenario.skill_hash,
        session_uuid: scenario.session_uuid,
        max_budget_cap: scenario.budget_cap,
        deadline_ttl_ms: scenario.ttl_ms,
        user_rule_sig_hash: scenario.sig_hash,
    };

    // Limitar el payload al límite de protocolo (64 KB) para evaluar la inspección semántica
    let bounded_payload = if scenario.payload.len() > 4096 {
        scenario.payload[..4096].to_vec()
    } else {
        scenario.payload
    };

    let packet = IpduPacket::new(header, bounded_payload);

    // Configurar contexto de tinte monotónico (proceso saliente a red externa)
    let mut taint_ctx = ProcessTaintContext::new(1001, "fuzz-agent", true);
    if scenario.is_medical_tainted {
        taint_ctx.contaminate_with(TaintTag::MEDICAL_PII);
    }
    if scenario.is_financial_tainted {
        taint_ctx.contaminate_with(TaintTag::FINANCIAL_DATA);
    }

    // Configurar política soberana del usuario
    let mut policy = UserGovernancePolicy::default();
    policy.max_budget_cap = scenario.policy_max_budget;
    policy.max_deadline_ms = 60_000;
    policy.deny_external_egress_if_tainted = true;
    policy.blacklist_skill(scenario.forbidden_skill);

    let mut firewall = CognitiveFirewall::new(policy.clone());

    // Ejecutar el pipeline de 3 pasos MSAC (NUNCA debe hacer panic)
    let decision = firewall.inspect_egress(&taint_ctx, &packet);

    // =========================================================================
    // INVARIANTES FORMALES DE SEGURIDAD COGNITIVA
    // =========================================================================

    // INVARIANTE 1: Proceso con tinte crítico no puede salir a internet
    if (scenario.is_medical_tainted || scenario.is_financial_tainted) && policy.deny_external_egress_if_tainted {
        assert_ne!(
            decision.verdict,
            Verdict::Allow,
            "VIOLACIÓN DE SEGURIDAD MSAC: Egreso permitido con tinte crítico activo"
        );
    }

    // INVARIANTE 2: Presupuesto nunca puede exceder el límite del usuario
    if scenario.budget_cap > scenario.policy_max_budget {
        assert_ne!(
            decision.verdict,
            Verdict::Allow,
            "VIOLACIÓN DE SEGURIDAD MSAC: Egreso permitido excediendo MAX_BUDGET_CAP"
        );
    }

    // INVARIANTE 3: Habilidad en lista negra jamás puede ser autorizada
    if scenario.skill_hash == scenario.forbidden_skill {
        assert_ne!(
            decision.verdict,
            Verdict::Allow,
            "VIOLACIÓN DE SEGURIDAD MSAC: Egreso permitido hacia habilidad bloqueada"
        );
    }
});
