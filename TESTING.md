# Reporte de Pruebas y Validación: Prototipo Capa 8 (RFC-ILP-2026)

Este documento detalla la metodología, cobertura y resultados de la suite de pruebas automatizadas desarrollada en **Rust** para validar la especificación de la **Capa 8 (Interaction Layer Protocol - ILP / ISO-7498-8 Draft)**.

---

## 1. Resumen Ejecutivo de Pruebas

| Módulo Evaluado | Archivo de Test | Pruebas | Resultado | Cobertura Funcional |
| :--- | :--- | :---: | :---: | :--- |
| **I-PDU Wire Format** | `tests/test_ipdu_wire.rs` | 8 | **100% PASS** | Empaquetado binario Big-Endian, Word 0 bitfields, cabecera canónica (36B), cabecera compacta (32B), defensa anti Allocation Bomb y bounds checking. |
| **Cognitive Firewall (MSAC)** | `tests/test_firewall_msac.rs` | 8 | **100% PASS** | Pipeline MSAC de 3 pasos: Taint Tracking, límites de usuario O(1), guardián heurístico SLM contra DLP y Prompt Injection, y Ring Buffer acotado contra agotamiento de memoria. |
| **Protocol Handshake** | `tests/test_handshake_simulation.rs` | 1 | **100% PASS** | Negociación completa del 3-Way Intent Handshake entre Cliente y Proveedor con auditoría en ambos firewalls. |
| **Total General** | **17 Pruebas** | **17** | **17 PASADAS** | **0 fallos, 0 errores, 0 ignoradas** |

---

## 2. Detalle de Pruebas por Componente

### 2.1. Núcleo I-PDU: Serialización Binaria y Formato de Red (`tests/test_ipdu_wire.rs`)

1. **`test_word0_packing_and_unpacking`**:
   - Valida la manipulación a nivel de bit del primer bloque de 32 bits (`Word 0`).
   - Verifica que `VER` (4 bits: `0x1`), `PERFORMATIVE` (6 bits), `AUTONOMY_TIER` (6 bits) y `COGNITIVE_POLICY_FLAGS` (16 bits) se empaquetan con shifts y máscaras sin interferencia entre campos adyacentes.
2. **`test_canonical_header_roundtrip`**:
   - Comprueba la serialización canónica de 36 bytes (288 bits) alineada a 32 bits con firma DID/ZKP de 64 bits.
   - Valida el invariante: `from_canonical_bytes(to_canonical_bytes(header)) == header`.
3. **`test_compact_256bit_header_roundtrip`**:
   - Comprueba la variante compacta estricta de 32 bytes (256 bits) con hash de firma truncado a 32 bits.
4. **`test_complete_packet_roundtrip`**:
   - Comprueba el encapsulamiento de cabecera fija + prefijo de longitud de 4 bytes + payload semántico variable (`Vec<u8>`).
5. **`test_unsupported_version_error`**:
   - Verifica el rechazo inmediato (`Err(IpduError::UnsupportedVersion)`) cuando el campo `VER` difiere de `0x1`.
6. **`test_buffer_underflow_error`**:
   - Garantiza la seguridad de memoria frente a paquetes incompletos o truncados en el socket de red (`Err(IpduError::BufferUnderflow)`).
7. **`test_validate_frame_bounds_allocation_bomb_defense`**:
   - Comprueba el blindaje preventivo contra Allocation Bombs: rechazo en $O(1)$ sin reservar heap si el prefijo declara más de `MAX_ILP_PAYLOAD_SIZE` (64 KB).
8. **`test_validate_frame_bounds_truncated_payload`**:
   - Garantiza que si la longitud declarada excede los bytes efectivamente disponibles en el buffer, se rechace con `Err(IpduError::TruncatedPayload)`.

---

### 2.2. Filtro de Reglas de Usuario: Cognitive Reference Monitor (`tests/test_firewall_msac.rs`)

Evalúa los 3 pasos atómicos de intercepción obligatoria (*Mandatory Semantic Access Control*) y la contención de memoria:

#### Paso 1: Taint Tracking en el Kernel (Sub-microsegundo)
1. **`test_msac_step1_clean_process_allowed`**:
   - Un proceso sin contaminar emitiendo un intent legítimo recibe `Verdict::Allow`.
2. **`test_msac_step1_medical_taint_blocks_external_egress`**:
   - Un proceso cuyo contexto leyó datos médicos (`TaintTag::MEDICAL_PII`) e intenta comunicarse hacia interfaces de red externas es bloqueado en seco con `Verdict::Drop` y código `-EPERM_COGNITIVE_POLICY` antes de evaluar el resto de la cabecera.

#### Paso 2: Reglas Soberanas de Usuario y Cabecera ($O(1)$)
3. **`test_msac_step2_budget_exceeded_drop`**:
   - Un paquete con `MAX_BUDGET_CAP` (60,000) superior al límite soberano del usuario (50,000) es descartado con `-EPERM_BUDGET_EXCEEDED`.
4. **`test_msac_step2_sandbox_required_drop`**:
   - Un paquete con `AUTONOMY_TIER >= 2` que no incluye el flag `REQUIRE_SANDBOXED_INFERENCE` es bloqueado con `-EPERM_SANDBOX_REQUIRED`.
5. **`test_msac_step2_forbidden_skill_drop`**:
   - Una petición dirigida a un `SKILL_NAMESPACE_HASH` incluido en la lista negra (`blacklisted_skills`) del usuario es bloqueada con `-EPERM_FORBIDDEN_SKILL`.

#### Paso 3: SLM Gatekeeper (Inspección Heurística / DLP)
6. **`test_msac_step3_gatekeeper_credit_card_drop`**:
   - Detecta números de tarjeta de crédito (Visa/Mastercard) en el payload semántico validados con el algoritmo de Luhn y descarta con `-EPERM_SEMANTIC_EXFILTRATION`.
7. **`test_msac_step3_gatekeeper_prompt_injection_drop`**:
   - Detecta intentos de subversión cognitiva (*Cross-Agent Prompt Injection*) como `"ignore previous instructions"` y descarta con `-EPERM_PROMPT_INJECTION`.

#### Resiliencia Operativa y Seguridad de Memoria
8. **`test_firewall_audit_log_ring_buffer_bounded`**:
   - Somete el monitor de referencia a ráfagas continuas de tráfico verificando que el Ring Buffer (`VecDeque`) descarte entradas antiguas en $O(1)$ y preserve su capacidad fija (`max_audit_entries`), previniendo agotamiento de memoria (Memory Exhaustion / OOM Killer).

---

### 2.3. Negociación Multi-Agente: 3-Way Intent Handshake (`tests/test_handshake_simulation.rs`)

1. **`test_full_3way_intent_handshake`**:
   - Simula el diálogo completo entre un Agente Cliente (OS-A) y un Agente Proveedor (OS-B) a través de sus respectivos firewalls cognitivos:
     1. `DISCOVER_SKILL`: Consulta semántica en la red.
     2. `PROPOSE_INTENT`: Propuesta de trabajo y presupuesto inicial ($200).
     3. `COUNTER_OFFER`: Contraoferta del proveedor cotizando precio y SLA ($220).
     4. `COMMIT_CONTRACT`: Compromiso formal, bloqueo de fondos en escrow y firma.
     5. `ATTEST_RESULT`: Entrega del resultado firmado con atestación verificable.
   - Confirma que ambos firewalls registran en su bitácora de auditoría cada paso conforme a las políticas del usuario.

---

## 3. Instrucciones de Reproducción

### Requisitos
- Rust toolchain (`rustc`, `cargo` versión 1.70+).

### Ejecución de Pruebas Unitarias
```bash
cargo test --verbose
```

Salida esperada:
```text
test test_msac_step1_clean_process_allowed ... ok
test test_firewall_audit_log_ring_buffer_bounded ... ok
test test_msac_step1_medical_taint_blocks_external_egress ... ok
test test_msac_step2_budget_exceeded_drop ... ok
test test_msac_step2_forbidden_skill_drop ... ok
test test_msac_step2_sandbox_required_drop ... ok
test test_msac_step3_gatekeeper_credit_card_drop ... ok
test test_msac_step3_gatekeeper_prompt_injection_drop ... ok
test test_full_3way_intent_handshake ... ok
test test_buffer_underflow_error ... ok
test test_canonical_header_roundtrip ... ok
test test_compact_256bit_header_roundtrip ... ok
test test_complete_packet_roundtrip ... ok
test test_unsupported_version_error ... ok
test test_validate_frame_bounds_allocation_bomb_defense ... ok
test test_validate_frame_bounds_truncated_payload ... ok
test test_word0_packing_and_unpacking ... ok

test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Ejecución de la Demostración Interactiva
```bash
cargo run
```
Muestra el desglose de bits de la cabecera I-PDU, su hexdump en el cable y la intercepción en vivo de los 6 casos de uso del firewall cognitivo con su bitácora forense estructurada.

---

## 4. Arquitectura de Fuzzing (`fuzz/` con `cargo-fuzz`)

Para pruebas de estrés continuas, detección de fugas de memoria con **AddressSanitizer** y validación de invariantes formales de seguridad cognitiva, el repositorio incluye una suite completa basada en `cargo-fuzz` y `libfuzzer-sys`:

```text
fuzz/
├── Cargo.toml
└── fuzz_targets/
    ├── fuzz_wire_parser.rs      # Target 1: Fuzzing de cable y roundtrip
    └── fuzz_msac_pipeline.rs     # Target 2: Fuzzing estructurado de invariantes MSAC
```

### 4.1. Blindaje Preventivo en el Parser (`src/ipdu/packet.rs`)
Antes de invocar el deserializador, se aplican validaciones deterministas en $O(1)$ sin reservar memoria en el heap:
- **`MAX_ILP_PAYLOAD_SIZE` (65,536 bytes / 64 KB):** Defensa activa contra *Allocation Bombs* (ataques de denegación de servicio por agotamiento de memoria OOM).
- **`validate_frame_bounds(raw: &[u8])`:** 
  1. Verificación de tamaño mínimo de trama (36 bytes cabecera + 4 bytes length prefix).
  2. Extracción segura con `.try_into()` sin panics.
  3. Comprobación aritmética con `checked_add` contra desbordamientos (*Integer Overflow*) en sistemas de 32 bits.

### 4.2. Mitigación de Agotamiento de Memoria en el Firewall (Ring Buffer Bounded)
Para ejecuciones prolongadas y campañas de fuzzing de millones de iteraciones:
- `CognitiveFirewall` implementa un **Ring Buffer** FIFO acotado mediante `VecDeque<AuditRecord>` con capacidad predeterminada [`DEFAULT_MAX_AUDIT_LOG_CAPACITY = 10_000`](file:///home/rober/Documentos/Capa8/src/governance/firewall.rs#L88).
- Evicción en $O(1)$ que descarta eventos antiguos al colmarse el búfer, neutralizando vectores de fuga de memoria o disparo del umbral `-rss_limit_mb=2048` (y el OOM Killer de Linux en producción).
- Constructor configurable `CognitiveFirewall::with_audit_capacity(policy, max_capacity)` para entornos embebidos o microcontroladores.

### 4.3. Arneses de Prueba

1. **Target 1: `fuzz_wire_parser` (`fuzz/fuzz_targets/fuzz_wire_parser.rs`)**
   - Somete a estrés los deserializadores `from_canonical_bytes`, `from_compact_bytes` y `from_bytes` con flujos arbitrarios de bytes corruptos.
   - Comprueba el invariante de roundtrip para cada paquete o cabecera válida:
     - Cabecera compacta (32B): idempotencia binaria y truncado determinista de firma.
     - Cabecera canónica (36B): idempotencia total de los 288 bits.
     - Paquete I-PDU completo: serialización y re-parsing idéntico.

2. **Target 2: `fuzz_msac_pipeline` (`fuzz/fuzz_targets/fuzz_msac_pipeline.rs`)**
   - Mediante **Property-Based Fuzzing** con `arbitrary` y semilla híbrida (`raw_bytes_header: [u8; 36]`), valida las 3 invariantes de seguridad formales:
   - **Invariante 1 (Integridad Forense):** Toda inspección de paquete DEBE generar un registro `AuditRecord` en `firewall.audit_log`.
   - **Invariante 2 (MSAC Paso 2 - Límite Presupuestario):** Si `header.max_budget_cap > policy.max_budget_cap`, el veredicto NUNCA puede ser `Verdict::Allow`.
   - **Invariante 3 (MSAC Paso 2 - Habilidad Prohibida):** Si `header.skill_namespace_hash == blacklisted_skill`, el veredicto NUNCA puede ser `Verdict::Allow`.

### 4.4. Instrucciones de Ejecución de Fuzzing
Requiere toolchain `nightly` de Rust y `cargo-fuzz`:

```bash
# 1. Instalar toolchain nightly y cargo-fuzz (si no están presentes)
rustup toolchain install nightly
cargo install cargo-fuzz

# 2. Correr 1,000,000 de mutaciones contra el parser binario I-PDU
cargo +nightly fuzz run fuzz_wire_parser -- -runs=1000000 -rss_limit_mb=2048

# 3. Correr 1,000,000 de mutaciones contra el Firewall MSAC y el SlmGatekeeper
cargo +nightly fuzz run fuzz_msac_pipeline -- -runs=1000000 -rss_limit_mb=2048

# Alternativa acotada por tiempo (ej. 60 segundos por arnés)
cargo +nightly fuzz run fuzz_wire_parser -- -max_total_time=60 -rss_limit_mb=2048
cargo +nightly fuzz run fuzz_msac_pipeline -- -max_total_time=60 -rss_limit_mb=2048
```

