#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ilp_core::{
    CognitiveFirewall,
    IpduPacket,
    ProcessTaintContext,
    TaintTag,
    UserGovernancePolicy,
    Verdict,
};
use ilp_core::ipdu::flags::CognitivePolicyFlags;
use ilp_core::ipdu::header::IpduHeader;
use ilp_core::ipdu::performatives::Performative;

#[derive(Arbitrary, Debug)]
struct FuzzMsacInput {
    raw_bytes_header: [u8; 36],
    payload: Vec<u8>,
    apply_medical_taint: bool,
    apply_financial_taint: bool,
    policy_budget_limit: u32,
    policy_ttl_limit: u32,
    blacklisted_skill: u64,
}

fuzz_target!(|input: FuzzMsacInput| {
    // 1. Intentar construir una cabecera válida desde los 36 bytes difusos
    // (Si los bits de versión o performativa son inválidos, forzamos una cabecera válida
    // para que el fuzzer penetre directamente en los 3 pasos del MSAC)
    let header = match IpduHeader::from_canonical_bytes(&input.raw_bytes_header) {
        Ok(h) => h,
        Err(_) => {
            let flags = CognitivePolicyFlags::from_bits_truncate(
                u16::from_be_bytes([input.raw_bytes_header[2], input.raw_bytes_header[3]])
            );
            IpduHeader {
                version: 0x1,
                performative: Performative::ProposeIntent,
                autonomy_tier: input.raw_bytes_header[1] & 0x3F,
                policy_flags: flags,
                skill_namespace_hash: u64::from_be_bytes(
                    input.raw_bytes_header[4..12].try_into().unwrap()
                ),
                session_uuid: u64::from_be_bytes(
                    input.raw_bytes_header[12..20].try_into().unwrap()
                ),
                max_budget_cap: u32::from_be_bytes(
                    input.raw_bytes_header[20..24].try_into().unwrap()
                ),
                deadline_ttl_ms: u32::from_be_bytes(
                    input.raw_bytes_header[24..28].try_into().unwrap()
                ),
                user_rule_sig_hash: u64::from_be_bytes(
                    input.raw_bytes_header[28..36].try_into().unwrap()
                ),
            }
        }
    };

    // Acotar el payload difuso a 8 KB para estresar el SlmGatekeeper (Paso 3: Luhn / Prompt Injection)
    let bounded_payload = if input.payload.len() > 8192 {
        input.payload[..8192].to_vec()
    } else {
        input.payload
    };

    let packet = IpduPacket {
        header: header.clone(),
        payload: bounded_payload,
    };

    // 2. Preparar el contexto de tinte monotónico del proceso
    let mut process_ctx = ProcessTaintContext::new(4242, "fuzz-worker-agent", true);
    if input.apply_medical_taint {
        process_ctx.contaminate_with(TaintTag::MEDICAL_PII);
    }
    if input.apply_financial_taint {
        process_ctx.contaminate_with(TaintTag::FINANCIAL_DATA);
    }

    // 3. Instanciar la política de usuario y el CognitiveFirewall
    let mut policy = UserGovernancePolicy::default();
    policy.max_budget_cap = input.policy_budget_limit;
    policy.max_deadline_ms = input.policy_ttl_limit;
    policy.blacklist_skill(input.blacklisted_skill);

    let mut firewall = CognitiveFirewall::new(policy);

    // 4. Ejecutar la intercepción atómica en 3 pasos
    let decision = firewall.inspect_egress(&process_ctx, &packet);

    // =========================================================================
    // VERIFICACIÓN DE INVARIANTES FORMALES (Property-Based Security Assertions)
    // =========================================================================

    // INVARIANTE 1 (Integridad Forense): Toda inspección DEBE generar un AuditRecord
    assert_eq!(
        firewall.audit_log.len(),
        1,
        "VIOLACIÓN FORENSE: inspect_egress no registró el evento en audit_log"
    );

    // INVARIANTE 2 (Paso 2 MSAC - Límite de Presupuesto):
    // Si el paquete pide más presupuesto que la política del usuario, el veredicto NUNCA puede ser Allow
    if header.max_budget_cap > input.policy_budget_limit {
        assert_ne!(
            decision.verdict,
            Verdict::Allow,
            "VIOLACIÓN MSAC PASO 2: Paquete con presupuesto excesivo fue permitido"
        );
    }

    // INVARIANTE 3 (Paso 2 MSAC - Habilidad Prohibida):
    // Si el skill_namespace_hash está en la lista negra, NUNCA puede ser Allow
    if header.skill_namespace_hash == input.blacklisted_skill {
        assert_ne!(
            decision.verdict,
            Verdict::Allow,
            "VIOLACIÓN MSAC PASO 2: Habilidad en blacklist fue permitida"
        );
    }
});
