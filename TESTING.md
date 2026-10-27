# Reporte de Pruebas y Validación: Prototipo Capa 8 (RFC-ILP-2026)

Este documento detalla la metodología, cobertura y resultados de la suite de pruebas automatizadas desarrollada en **Rust** para validar la especificación de la **Capa 8 (Interaction Layer Protocol - ILP / ISO-7498-8 Draft)**.

---

## 1. Resumen Ejecutivo de Pruebas

| Módulo Evaluado | Archivo de Test | Pruebas | Resultado | Cobertura Funcional |
| :--- | :--- | :---: | :---: | :--- |
| **I-PDU Wire Format** | `tests/test_ipdu_wire.rs` | 6 | **100% PASS** | Empaquetado binario Big-Endian, Word 0 bitfields, cabecera canónica (36B), cabecera compacta (32B), control de errores. |
| **Cognitive Firewall (MSAC)** | `tests/test_firewall_msac.rs` | 7 | **100% PASS** | Pipeline MSAC de 3 pasos: Taint Tracking, límites de usuario O(1), guardián heurístico SLM contra DLP y Prompt Injection. |
| **Protocol Handshake** | `tests/test_handshake_simulation.rs` | 1 | **100% PASS** | Negociación completa del 3-Way Intent Handshake entre Cliente y Proveedor con auditoría en ambos firewalls. |
| **Total General** | **14 Pruebas** | **14** | **14 PASADAS** | **0 fallos, 0 errores, 0 ignoradas** |

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

---

### 2.2. Filtro de Reglas de Usuario: Cognitive Reference Monitor (`tests/test_firewall_msac.rs`)

Evalúa los 3 pasos atómicos de intercepción obligatoria (*Mandatory Semantic Access Control*):

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
test test_msac_step1_medical_taint_blocks_external_egress ... ok
test test_msac_step2_budget_exceeded_drop ... ok
test test_msac_step2_forbidden_skill_drop ... ok
test test_msac_step3_gatekeeper_credit_card_drop ... ok
test test_msac_step3_gatekeeper_prompt_injection_drop ... ok
test test_msac_step2_sandbox_required_drop ... ok
test test_full_3way_intent_handshake ... ok
test test_buffer_underflow_error ... ok
test test_canonical_header_roundtrip ... ok
test test_complete_packet_roundtrip ... ok
test test_compact_256bit_header_roundtrip ... ok
test test_unsupported_version_error ... ok
test test_word0_packing_and_unpacking ... ok

test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Ejecución de la Demostración Interactiva
```bash
cargo run
```
Muestra el desglose de bits de la cabecera I-PDU, su hexdump en el cable y la intercepción en vivo de los 6 casos de uso del firewall cognitivo con su bitácora forense estructurada.
