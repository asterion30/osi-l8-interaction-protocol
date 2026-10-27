//! Simulation of the complete 3-Way Intent Handshake (RFC-ILP-2026 Section 5.2)
//! Client Agent (OS-A) <---> Cognitive Firewalls <---> Provider Agent (OS-B)

use ilp_core::governance::{CognitiveFirewall, ProcessTaintContext, UserGovernancePolicy, Verdict};
use ilp_core::ipdu::{CognitivePolicyFlags, IpduPacket, Performative};

#[test]
fn test_full_3way_intent_handshake() {
    let session_uuid: u64 = 0xCAFE_BABE_0000_1234;
    let skill_hash: u64 = 0x9876_5432_10AB_CDEF; // CAD to G-Code CNC skill
    let user_a_sig: u64 = 0x1111_2222_3333_4444;
    let user_b_sig: u64 = 0x5555_6666_7777_8888;

    // Firewalls de ambos extremos (Client OS-A y Provider OS-B)
    let policy_a = UserGovernancePolicy::default();
    let mut firewall_a = CognitiveFirewall::new(policy_a);

    let policy_b = UserGovernancePolicy::default();
    let mut firewall_b = CognitiveFirewall::new(policy_b);

    let client_proc = ProcessTaintContext::new(501, "agent-client-cad", true);
    let prov_proc = ProcessTaintContext::new(702, "agent-provider-cnc", true);

    // 1. DISCOVER_SKILL: El cliente busca agentes con habilidad CNC
    let pdu_discover = IpduPacket::discover_skill(
        skill_hash,
        session_uuid,
        CognitivePolicyFlags::ALLOW_DELEGATION,
        "query: convert stl cad mesh to Haas 5-axis G-Code",
    );
    assert_eq!(pdu_discover.header.performative, Performative::DiscoverSkill);
    let dec1 = firewall_a.inspect_egress(&client_proc, &pdu_discover);
    assert_eq!(dec1.verdict, Verdict::Allow);

    // 2. PROPOSE_INTENT: El cliente propone el trabajo con un presupuesto de 200 tokens/satoshis
    let pdu_propose = IpduPacket::propose_intent(
        skill_hash,
        session_uuid,
        2, // Autonomy tier 2
        200,
        15_000,
        CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE,
        user_a_sig,
        "{\"mesh_id\": \"cad_turbo_impeller.stl\", \"material\": \"Titanium-Ti6Al4V\"}",
    )
    .unwrap();
    assert_eq!(pdu_propose.header.performative, Performative::ProposeIntent);
    let dec2 = firewall_a.inspect_egress(&client_proc, &pdu_propose);
    assert_eq!(dec2.verdict, Verdict::Allow);

    // 3. COUNTER_OFFER: El proveedor cotiza 220 unidades por requerir titanio grado aeroespacial
    let pdu_counter = IpduPacket::counter_offer(
        session_uuid,
        skill_hash,
        220,
        15_000,
        user_b_sig,
        "{\"price\": 220, \"sla_sec\": 45, \"attestation\": \"ISO-9001-AS9100D\"}",
    )
    .unwrap();
    assert_eq!(pdu_counter.header.performative, Performative::CounterOffer);
    let dec3 = firewall_b.inspect_egress(&prov_proc, &pdu_counter);
    assert_eq!(dec3.verdict, Verdict::Allow);

    // 4. COMMIT_CONTRACT: El cliente valida el precio con sus políticas, bloquea escrow y confirma
    let pdu_commit = IpduPacket::commit_contract(
        session_uuid,
        skill_hash,
        220,
        user_a_sig,
        "{\"escrow_tx\": \"tx_0x9fbc18...\", \"status\": \"FUNDS_LOCKED\"}",
    )
    .unwrap();
    assert_eq!(pdu_commit.header.performative, Performative::CommitContract);
    let dec4 = firewall_a.inspect_egress(&client_proc, &pdu_commit);
    assert_eq!(dec4.verdict, Verdict::Allow);

    // 5. ATTEST_RESULT: El proveedor entrega el código G firmado con atestación verificable
    let header_attest = ilp_core::ipdu::IpduHeader::new(
        Performative::AttestResult,
        1,
        CognitivePolicyFlags::EMPTY,
        skill_hash,
        session_uuid,
        220,
        30_000,
        user_b_sig,
    )
    .unwrap();
    let pdu_attest = IpduPacket::new(
        header_attest,
        b"{\"gcode_artifact_sha256\": \"e3b0c442...\", \"zkp_proof\": \"zk_proof_data\"}".to_vec(),
    );
    assert_eq!(pdu_attest.header.performative, Performative::AttestResult);
    let dec5 = firewall_b.inspect_egress(&prov_proc, &pdu_attest);
    assert_eq!(dec5.verdict, Verdict::Allow);

    // Verificamos que ambos firewalls registraron todos los eventos
    assert_eq!(firewall_a.audit_log.len(), 3);
    assert_eq!(firewall_b.audit_log.len(), 2);
}
