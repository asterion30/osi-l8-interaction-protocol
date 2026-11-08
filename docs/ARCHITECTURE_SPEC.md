# RFC-ILP-2026: Interaction Layer Protocol (ILP) — Architectural Specification & Future Kernel Roadmap

This document serves as the formal theoretical specification and extended architectural blueprint for the **Interaction Layer Protocol (ILP)** within the extended OSI 8-Layer model, specifically outlining the design of the **Mandatory Semantic Access Control (MSAC)** subsystem and the future roadmap for in-kernel **Linux eBPF / LSM** enforcement.

---

## 1. Architectural Motivation: The Semantic Boundary of Layer 7

Historically, the OSI reference model (ISO/IEC 7498-1) established seven layers terminating at Layer 7 (Application). While Application Layer protocols (HTTP, gRPC, WebSocket) solve syntax, encoding, routing, and reliable packet transfer, they are fundamentally **agnostic to intent, autonomy tiers, economic budget bounds, and semantic data contamination**.

With the advent of autonomous AI agent workflows (Anthropic MCP, Google A2A, AutoGen), agents execute non-deterministic multi-turn tool calls. Transmitting unstructured JSON-RPC text payloads directly over Layer 7 introduces systemic vulnerabilities:

1. **Semantic Ambiguity at Line Rate**: Traditional firewalls cannot inspect multi-step prompt injection or data exfiltration without running full LLM inference on every ingress/egress frame.
2. **Denial of Wallet & Runaway Loops**: Adversarial agents can enter unconstrained negotiation loops, consuming compute budgets and API tokens without hard operational ceilings.
3. **Implicit Data Contamination**: When an agent reads classified data (e.g., medical records, credentials), application-layer proxies cannot guarantee monotonic taint tracking across child processes or external network sockets.

---

## 2. Formal Definition of Layer 8 (The Interaction Layer)

Layer 8 standardizes **agent-to-agent negotiation, cognitive policy enforcement, and autonomous interaction governance**.

```
+-------------------------------------------------------------------------+
| Layer 8: Interaction Layer Protocol (ILP / I-PDU)                       |
|   • Sovereign User Governance Policy (CRM / MSAC Engine)                |
|   • Autonomy Tiers (0..63) & Deterministic Budget Caps (32-bit)          |
|   • 3-Way Intent Handshake FSM (Discover -> Propose -> Commit)          |
|   • Monotonic Taint Tracking & Cryptographic Result Attestation (ZKP)   |
+-------------------------------------------------------------------------+
| Layer 7: Application (HTTP/2, HTTP/3, gRPC, MCP JSON-RPC, WebSocket)   |
+-------------------------------------------------------------------------+
| Layer 6: Presentation (TLS 1.3 / mTLS / X.509)                          |
+-------------------------------------------------------------------------+
| Layer 5: Session (TCP Sockets, QUIC Streams, Domain Sockets)            |
+-------------------------------------------------------------------------+
| Layers 1-4: Transport, Network, Data Link, Physical (IP, Ethernet)      |
+-------------------------------------------------------------------------+
```

---

## 3. Mandatory Semantic Access Control (MSAC) Subsystem

The Cognitive Reference Monitor (CRM) applies a 3-step deterministic evaluation pipeline to every outgoing I-PDU:

```
[Agent Process] 
       │
       ▼ (Socket Egress)
┌────────────────────────────────────────────────────────┐
│ Step 1: Process Taint Audit (Sub-microsecond)          │
│   • Evaluates ProcessTaintContext vs Policy Bitmask    │
│   • Immediate DROP if tainted with PII/Financial/Creds │
└──────────────────────────┬─────────────────────────────┘
                           │ Passed
                           ▼
┌────────────────────────────────────────────────────────┐
│ Step 2: Binary Header & Sovereign Rule Check (O(1))    │
│   • Validates Autonomy Tier <= Policy.max_autonomy     │
│   • Enforces Budget Cap <= Policy.max_budget           │
│   • Rejects Blacklisted Skill Hashes (FNV-1a 64-bit)   │
└──────────────────────────┬─────────────────────────────┘
                           │ Passed
                           ▼
┌────────────────────────────────────────────────────────┐
│ Step 3: Fast-Path Semantic Guard (SLM Gatekeeper)      │
│   • Regex & token entropy scan (< 500 ns)              │
│   • Blocks Prompt Injections & Exfiltration patterns   │
└──────────────────────────┬─────────────────────────────┘
                           │ Passed
                           ▼
                    [Network Wire]
```

---

## 4. Future In-Kernel Integration: Linux eBPF / LSM Roadmap (Phase 4)

In the current version (`v0.1.0`), `ilp-core` operates as a **Userspace Reference Monitor and Sidecar Proxy**. The architectural vision of RFC-ILP-2026 targets native operating system kernel integration.

### 4.1 Linux LSM & eBPF Socket Hooks
The long-term objective is to move Step 1 and Step 2 of the MSAC pipeline into the Linux kernel using **eBPF (Extended Berkeley Packet Filter)** and **Linux Security Modules (LSM)**:

- `BPF_PROG_TYPE_CGROUP_SOCKOPT` / `sock_ops`: Intercept agent socket creation and associate kernel cgroups with the agent's Sovereign User Policy.
- `lsm/socket_sendmsg`: Read the 36-byte canonical I-PDU header directly from kernel space before packet encryption in TLS, returning `-EPERM` instantly if budget caps or taint rules are violated.
- `bpf_lsm_file_open` & `bpf_lsm_inode_permission`: Implement native kernel taint propagation. If a sandboxed agent reads an extended attribute (`security.ilp_taint = medical_pii`), the kernel sets the corresponding bit in the process credentials (`task_struct->security`), preventing any subsequent `sendmsg()` to external non-loopback interfaces.

### 4.2 Windows & Darwin Equivalents
- **Windows**: WFP (Windows Filtering Platform) Callout Driver at the `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` layers.
- **macOS / Darwin**: Endpoint Security Framework (`es_event_socket_t`) and NetworkExtension transparent proxy providers.

---

## 5. Specification Reference Documents

- **Draft Standard**: ISO/IEC 7498-8 (Information technology — Open Systems Interconnection — The Interaction Layer Protocol)
- **RFC Track**: RFC-ILP-2026 (Interaction Layer Protocol Specification)
- **Reference Implementation**: `ilp-core` (`src/ipdu`, `src/governance`, `src/transport`, `src/bridge`)
