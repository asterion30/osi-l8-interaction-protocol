# ilp-core: Reference Implementation & Research Prototype for OSI Layer 8 (ILP)

[![CI & Verification](https://github.com/asterion30/osi-l8-interaction-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/asterion30/osi-l8-interaction-protocol/actions/workflows/ci.yml)
[![Core: Zero External Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(std%20only)-brightgreen.svg)](#)
[![Performance: Sub-Microsecond](https://img.shields.io/badge/MSAC%20Latency-%3C%201%20%C2%B5s-blue.svg)](#benchmarks-de-latencia-y-rendimiento)
[![Interoperability: MCP & A2A](https://img.shields.io/badge/Ecosystem-Anthropic%20MCP%20%7C%20Google%20A2A-purple.svg)](#why-now--how-ilp-complements-mcp--a2a)
[![Specification: ISO/IEC 7498-8 Draft](https://img.shields.io/badge/Draft-ISO%2FIEC%207498--8-blue.svg)](docs/ARCHITECTURE_SPEC.md)
[![RFC Track: Experimental / Proposed Standard](https://img.shields.io/badge/RFC-RFC--ILP--2026-orange.svg)](#)
[![Code License: MIT](https://img.shields.io/badge/Code%20License-MIT-green.svg)](LICENSE)

> **Headline:** *ilp-core: Reference Implementation & Research Prototype for the Interaction Layer Protocol (ILP) — A zero-dependency Rust library and userspace semantic firewall (MSAC) for autonomous AI agent communication.*

---

## 📊 Current Maturity & Implementation Status

Para proporcionar total transparencia a auditores de seguridad, ingenieros de sistemas e investigadores, la siguiente tabla resume qué componentes están **plenamente implementados y verificados en código ejecutable**, cuáles son pruebas de concepto y cuáles corresponden a la especificación arquitectónica del Kernel:

| Componente del Protocolo | Estado de Madurez | Ubicación en el Repositorio |
| :--- | :---: | :--- |
| **Binary I-PDU Wire Framing (32B/36B)** | ✅ **Implemented & Fuzz-Tested** | [`src/ipdu/`](src/ipdu/) (Header, Packet, Word 0, Length-Prefix, TrailingBytes check) |
| **Userspace MSAC Semantic Firewall** | ✅ **Implemented & Auditable** | [`src/governance/`](src/governance/) (Pipeline de 3 pasos, Ring Buffer, HeuristicGatekeeper) |
| **Monotonic Taint Tracking & Origin Traceability** | ✅ **Implemented** | [`src/governance/taint.rs`](src/governance/taint.rs) (`TaintEvent`, `source_descriptor`, private fields) |
| **Zero-Deps Policy Engine (`.conf`)** | ✅ **Implemented** | [`src/governance/policy.rs`](src/governance/policy.rs), [`policies/default_msac.conf`](policies/default_msac.conf) |
| **Stateful TCP Transport & 3-Way Handshake FSM** | ✅ **Implemented** | [`src/transport/`](src/transport/) (`SessionRole::Initiator` vs `Responder`, atomic mutation) |
| **MCP (JSON-RPC) Shield Adapter & E2E Proxy** | ✅ **Implemented & Verified E2E** | [`src/bridge/`](src/bridge/), [`tests/test_mcp_proxy_e2e.rs`](tests/test_mcp_proxy_e2e.rs) (TCP proxy con prueba de no-ejecución) |
| **Linux Kernel eBPF / LSM Socket Hooks** | 🗺️ **Architectural Specification (Roadmap)** | [`docs/ARCHITECTURE_SPEC.md`](docs/ARCHITECTURE_SPEC.md) (Fase 4 del estándar) |

---

## ⚠️ Assumptions & Known Limitations

1. **Userspace Reference Monitor (No Ring 0 Yet):**  
   En la versión actual (`v0.1.0`), el firewall semántico `CognitiveFirewall` y el contexto `ProcessTaintContext` se ejecutan como un **monitor de referencia cooperativo en espacio de usuario** (*Userspace Reference Monitor / Sidecar Proxy*). No intercepta llamadas al sistema en Ring 0 a nivel de kernel todavía. La especificación formal para ganchos eBPF (`lsm/socket_sendmsg`, `bpf_lsm_file_open`) está detallada en [`docs/ARCHITECTURE_SPEC.md`](docs/ARCHITECTURE_SPEC.md).
2. **Taint Tracking en Espacio de Usuario:**  
   La propagación de tinte depende de que el runtime o el proxy sidecar invoque `apply_taint(tag, descriptor)`. El contexto encapsula estrictamente sus campos y bitmask haciéndolos inmutables/monotónicos desde código externo. El aislamiento contra procesos hostiles requiere confinamiento de contenedor (cgroups / seccomp / Firecracker) hasta que los hooks de kernel estén terminados.
3. **SLM / Heuristic Gatekeeper:**  
   El paso 3 del firewall utiliza heurísticas rápidas (< 500 ns) de entropía, validación de Luhn para números de tarjeta de crédito y patrones adversariales para prevención de exfiltración e inyección de prompts, diseñado para ser complementado por un modelo SLM local en GPU/NPU cuando la latencia lo permita.

---

## ⚡ Why Now & How ILP Complements MCP / A2A

Frente a la adopción generalizada de frameworks agénticos y protocolos de herramientas como **Model Context Protocol (MCP)** de Anthropic y **A2A** de Google, la industria enfrenta un vacío crítico de seguridad: **las llamadas de herramientas y el paso de mensajes en texto plano/JSON no tienen gobernanza determinista en tiempo de ejecución**.

**ILP no busca reemplazar MCP ni HTTP.** ILP actúa como el **guardaespaldas binario (Egress Sidecar Proxy)** que envuelve y protege las conexiones de los agentes:

```text
+-------------------+       JSON-RPC        +------------------------+       I-PDU       +-------------------+
|  Agente / LLM     | --------------------> | ILP MSAC Proxy Sidecar | ----------------> | Herramienta / API |
| (Claude, AutoGen) |   tools/call (...)    |  • Taint DLP (Medical) |   Socket TCP/TLS  |  (Servidor Remoto)|
|                   |                       |  • Prompt Guard (<1µs) |                   |                   |
+-------------------+                       +------------------------+                   +-------------------+
```

---

## 🔬 Benchmarks Científicamente Reproducibles (100,000 Muestras Amortizadas)

El micro-benchmark de rendimiento fue ejecutado tras un periodo de calentamiento (*warmup*) de 10,000 iteraciones, midiendo en lotes amortizados de 100 operaciones por muestra (1,000 muestras = 100,000 operaciones totales) con `std::hint::black_box` en modo `--release`. La amortización por lotes elimina la distorsión del reloj del sistema (`vDSO clock_gettime` ~15-25 ns).

- **Entorno de Prueba**: Linux `x86_64` (AMD FX-8320 Eight-Core Processor), Perfil de compilación: `release` optimizado con LLVM.
- **Comando de Reproducción**: `./scripts/run_benchmarks.sh` o `cargo run --release --example benchmark_latency`.
- **Informe Completo**: [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md).

| Operación / Subsistema | Tamaño / Formato | Mediana (p50) | Percentil 95 (p95) | Percentil 99 (p99) | Máximo | Desviación Estándar (σ) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **I-PDU Header Parsing** | 36 Bytes (Canónico) | **26.9 ns** | 26.9 ns | 26.9 ns | 284.1 ns | ±8.1 ns |
| **I-PDU Packet Wire Roundtrip** | 512B Payload | **112.6 ns** | 127.0 ns | 178.3 ns | 579.2 ns | ±25.9 ns |
| **MSAC Semantic Firewall Egress** | 3 Pasos Completos | **908.6 ns** | 1.23 µs | 1.46 µs | 1.69 µs | ±120.2 ns |
| **JSON-RPC String Scan (Baseline)** | 512B Texto Plano | **345.3 ns** | 372.1 ns | 557.6 ns | 903.0 ns | ±41.3 ns |

> **Overhead Absoluto del Monitor en Espacio de Usuario (ns/op):** El parseo binario I-PDU insume ~27 ns/op, y el Firewall Cognitivo MSAC ejecuta su inspección en menos de un microsegundo (**p50 = 908.6 ns**), garantizando contención estricta sin penalizar los tiempos de inferencia de los LLMs.

---

## 🚀 Inicio Rápido (Quickstart)

```bash
# 1. Ejecutar la suite completa de 40 pruebas de integración y unitarias
cargo test --all-targets --all-features

# 2. Correr el benchmark formal reproducible y generar docs/BENCHMARK_RESULTS.md
./scripts/run_benchmarks.sh

# 3. Demostración en vivo: Dos agentes comunicándose por sockets TCP reales con handshake FSM
cargo run --example live_agent_proxy

# 4. Demostración del Escudo MCP: Protección contra Prompt Injection en JSON-RPC
cargo run --example mcp_shield_demo --features mcp

# 5. Demostrador CLI interactivo con hexdump en vivo de tramas I-PDU
cargo run
```

---

## Tabla de Contenidos

- [1. Especificación Arquitectónica Completa (docs/ARCHITECTURE_SPEC.md)](docs/ARCHITECTURE_SPEC.md)
- [2. Formato de Cabecera Binaria I-PDU](#formato-de-cabecera-binaria-i-pdu)
- [3. Máquina de Estados Finita (FSM) del Transporte](#máquina-de-estados-finita-fsm-del-transporte)
- [4. Motor de Políticas Declarativas (.conf)](#motor-de-políticas-declarativas-conf)
- [5. El Firewall Cognitivo (MSAC) y Trazabilidad de Taint](#el-firewall-cognitivo-msac-y-trazabilidad-de-taint)
- [6. Guía de Usuario y Traslado a Diferentes Entornos (docs/USER_MANUAL.md)](docs/USER_MANUAL.md)
- [7. Resultados de Benchmarks (docs/BENCHMARK_RESULTS.md)](docs/BENCHMARK_RESULTS.md)
- [Licenciamiento y Cita](#licenciamiento)

---

## Formato de Cabecera Binaria I-PDU

La cabecera canónica I-PDU se estructura como un bloque binario alineado a 32 bits de **36 bytes (288 bits)** en Network Byte Order (Big-Endian):

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  VER  |  PERFORMATIVE | AUTONOMY_TIER |   COGNITIVE_POLICY_FLAGS      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+          SKILL_NAMESPACE_HASH (64 bits - FNV-1a / SimHash)    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+              NEGOTIATION_SESSION_UUID (64 bits)               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       MAX_BUDGET_CAP (32 bits)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      DEADLINE_TTL_MS (32 bits)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+               USER_RULE_SIG_HASH (64 bits - DID/ZKP)          +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    LENGTH-PREFIX (4 bytes Big-Endian)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    SEMANTIC PAYLOAD (0 .. 64 KB, acotado contra OOM)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Campos Clave de la Cabecera
- **`SKILL_NAMESPACE_HASH` (64 bits):** Hash no criptográfico FNV-1a (o SimHash de intención) calculado sobre el identificador de la habilidad/herramienta (ej. `tools/call:calcular_riesgo`) para posibilitar enrutamiento y filtrado de políticas en $O(1)$ sin asignación en el heap.
- **`USER_RULE_SIG_HASH` (64 bits):** Campo de 64 bits reservado como *placeholder* para firmas criptográficas de usuario (ej. Ed25519 o compromisos de atestación mTLS/DID) orientadas a la verificación de soberanía en capas de infraestructura.
- **`NEGOTIATION_SESSION_UUID` (64 bits):** Identificador unívoco de la conversación agéntica derivado determinísticamente del identificador de llamada o del handshake inicial.

### Performativas del Protocolo (Speech Acts de 6 bits)
1. `0x01` — `DISCOVER_SKILL`: Consulta semántica en la red.
2. `0x02` — `PROPOSE_INTENT`: Propuesta formal de objetivo con presupuesto y SLA inicial.
3. `0x03` — `COUNTER_OFFER`: Ajuste bilateral de precio o condiciones.
4. `0x04` — `COMMIT_CONTRACT`: Compromiso y firma de contrato de ejecución.
5. `0x05` — `REJECT_POLICY`: Notificación de rechazo por violación de gobernanza.
6. `0x06` — `ATTEST_RESULT`: Entrega de resultados con atestaciones criptográficas (VC / ZKP).

---

## Máquina de Estados Finita (FSM) del Transporte

La capa de sesión (`src/transport/session.rs`) formaliza la interacción mediante la estructura `IlpSession<S>` y la FSM `SessionState`:

```text
       [ Idle ]
          │
          ├─────────────────────────┐
          ▼ (DiscoverSkill)         ▼ (ProposeIntent)
   [ DiscoverySent ]       [ IntentProposed ] ◄──┐ (CounterOffer)
          │                         │            │
          │ (ProposeIntent)         ├────────────┘
          ▼                         ▼ (CommitContract)
   [ IntentProposed ]     [ ContractCommitted ]
                                    │
                                    ▼ (AttestResult)
                        [ Terminated(Completed) ]
```

- **Transiciones estrictas:** Si un agente envía `CommitContract` estando en `Idle`, el transporte rechaza atómicamente con `Err(IpduError::InvalidStateTransition)`.
- **Alineación de Sesión:** Si un paquete llega con un `session_uuid` distinto al de la sesión activa, se aborta con `Err(IpduError::SessionMismatch)`.
- **Timeouts:** Los métodos de socket configuran `set_read_timeout` y `set_write_timeout` a partir del `deadline_ttl_ms`. Si expira, se emite `Err(IpduError::DeadlineExpired)` y el estado pasa a `Terminated(Timeout)`.

---

## Motor de Políticas Declarativas (`.conf`)

Las reglas del usuario se desacoplan del código y se cargan sin recompilar mediante un parser determinista *zero-dependencies*:

```ini
# policies/default_msac.conf
user_did = did:key:z6MkhaXgBZDvotDkL5257faiz48xzpq2541
max_budget_cap = 50000
max_autonomy_tier = 3
max_deadline_ms = 15000
require_sandbox_above_tier = 2
deny_external_egress_if_tainted = true
blacklist_skill = 0xDEADBEEF00000001
blacklist_skill = 0xBAD0CAFE00000002
```

Carga en código:
```rust
let conf = std::fs::read_to_string("policies/default_msac.conf")?;
let policy = UserGovernancePolicy::from_conf_str(&conf)?;
let mut firewall = CognitiveFirewall::new(policy);
```

---

## El Firewall Cognitivo (MSAC) y Trazabilidad de Taint

El pipeline MSAC evalúa obligatoriamente cada paquete saliente en 3 pasos:

1. **Paso 1: Auditoría de Tinte y Trazabilidad Forense:**
   - Si `process.is_external_egress` es verdadero y la política prohíbe salida con tinte, se bloquea el paquete.
   - Cada evento de tinte registra su origen: `proc.apply_taint(TaintTag::MEDICAL_PII, "read:/var/lib/records.db")`.
   - El log forense (`AuditRecord`) incluye los descriptores de origen exactos de la contaminación.
2. **Paso 2: Evaluación Determinista de Cabecera ($O(1)$):**
   - Valida techos de autonomía, presupuestos máximos, caducidad de TTL y listas negras de habilidades (`blacklist_skill`).
3. **Paso 3: Guardián SLM y Filtro DLP:**
   - Inspección semántica de texto para detección de números de tarjetas de crédito e intentos de prompt injection.
4. **Ring Buffer Bounded:**
   - Registro forense acotado en memoria (`VecDeque`, 10,000 entradas por defecto) para prevenir ataques de agotamiento de memoria (*Memory Exhaustion*).

---

## Estructura del Repositorio

```text
osi-l8-interaction-protocol/
├── README.md                                             # Este documento técnico consolidado
├── TESTING.md                                            # Guía y reporte de pruebas automatizadas
├── Cargo.toml                                            # Definición de crate ilp-core (zero-deps por defecto)
├── LICENSE                                               # Licencia de código MIT
├── LICENSE-DOCS                                          # Licencia de documentación CC BY 4.0
├── policies/
│   └── default_msac.conf                                 # Archivo de políticas declarativas de ejemplo
├── scripts/
│   └── run_benchmarks.sh                                 # Script de benchmark estadístico reproducible
├── docs/
│   ├── ARCHITECTURE_SPEC.md                              # Especificación teórica OSI L8 y roadmap eBPF/LSM
│   ├── BENCHMARK_RESULTS.md                              # Resultados empíricos de benchmark (p50/p95/p99)
│   └── USER_MANUAL.md                                    # Manual de usuario para migración de entornos
├── src/
│   ├── lib.rs                                            # Re-exportaciones públicas de la biblioteca
│   ├── ipdu/                                             # Cabeceras binarias, empaquetado y performativas
│   │   ├── flags.rs                                      # CognitivePolicyFlags (16 bits)
│   │   ├── performatives.rs                              # Speech acts (Discover, Propose, Commit, Attest, Reject)
│   │   ├── header.rs                                     # IpduHeader e IpduError
│   │   └── packet.rs                                     # IpduPacket y Length-Prefix bounds checking
│   ├── governance/                                       # Firewall Cognitivo (MSAC / CRM)
│   │   ├── taint.rs                                      # TaintTag, TaintEvent, ProcessTaintContext
│   │   ├── policy.rs                                     # UserGovernancePolicy y parser .conf
│   │   ├── gatekeeper.rs                                 # SLM Gatekeeper (DLP y prompt injection)
│   │   └── firewall.rs                                   # CognitiveFirewall y Ring Buffer forense
│   ├── transport/                                        # Capa de transporte y sesión con estado
│   │   ├── mod.rs                                        # IlpStream sobre sockets TCP / Read+Write
│   │   └── session.rs                                    # IlpSession y FSM de 3-Way Intent Handshake
│   ├── bridge/                                           # Escudo de compatibilidad con MCP JSON-RPC
│   └── main.rs                                           # Demostrador interactivo CLI
├── tests/                                                # 40 tests de integración y verificación E2E
│   ├── test_ipdu_wire.rs                                 # Fuzz, bounds checking y simetría binaria (9 tests)
│   ├── test_firewall_msac.rs                             # Validación de políticas .conf, taint y MSAC (13 tests)
│   ├── test_transport_fsm.rs                             # FSM de roles (Initiator/Responder) y plazos (5 tests)
│   ├── test_tcp_transport.rs                             # Sockets TCP reales y contención OOM (4 tests)
│   ├── test_handshake_simulation.rs                      # Simulación multi-turno 3-Way Handshake (1 test)
│   ├── test_mcp_bridge.rs                                # Mapeo estricto de métodos y error types (7 tests)
│   └── test_mcp_proxy_e2e.rs                             # Proxy TCP E2E con prueba de no-ejecución (1 test)
└── examples/
    ├── benchmark_latency.rs                              # Benchmark estadístico riguroso (p50, p95, p99)
    ├── live_agent_proxy.rs                               # Comunicación en vivo entre 2 agentes por TCP
    └── mcp_shield_demo.rs                                # Demostración del escudo MCP contra Prompt Injection
```

---

## Licenciamiento

- **Código fuente, implementaciones y scripts:** [Licencia MIT](LICENSE).
- **Especificaciones conceptuales y documentación:** [Creative Commons Attribution 4.0 (CC BY 4.0)](LICENSE-DOCS).

## Cita Académica

```bibtex
@techreport{ilp2026capa8,
  author       = {Rober and contributors},
  title        = {ilp-core: Reference Implementation and Userspace Specification for OSI Layer 8 Interaction Layer Protocol},
  institution  = {Interaction Layer Protocol Working Group},
  number       = {ISO/IEC 7498-8 Draft / RFC-ILP-2026},
  year         = {2026},
  note         = {Available at: https://github.com/asterion30/osi-l8-interaction-protocol}
}
```
