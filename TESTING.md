# Reporte de Pruebas y Validación: Prototipo Capa 8 (RFC-ILP-2026)

Este documento detalla la metodología, cobertura y resultados de la suite de pruebas automatizadas desarrollada en **Rust** para validar la especificación de la **Capa 8 (Interaction Layer Protocol - ILP / ISO-7498-8 Draft)**.

---

## 1. Resumen Ejecutivo de Pruebas

| Módulo Evaluado | Archivo de Test | Pruebas | Resultado | Cobertura Funcional |
| :--- | :--- | :---: | :---: | :--- |
| **I-PDU Wire Format** | `tests/test_ipdu_wire.rs` | 9 | **100% PASS** | Empaquetado binario Big-Endian, Word 0 bitfields, cabecera canónica (36B), cabecera compacta (32B), defensa anti Allocation Bomb, rechazo estricto de bytes sobrantes (`TrailingBytes`) y bounds checking. |
| **Cognitive Firewall (MSAC)** | `tests/test_firewall_msac.rs` | 13 | **100% PASS** | Pipeline MSAC de 3 pasos: Taint Tracking monotónico con encapsulamiento estricto, parser declarativo `.conf` con rechazo de duplicados y límites de tier (<= 63), límites O(1), DLP/Prompt Injection y Ring Buffer acotado. |
| **Transport Session & FSM** | `tests/test_transport_fsm.rs` | 5 | **100% PASS** | Máquina de estados finita por roles (`SessionRole::Initiator` vs `SessionRole::Responder`), mutación atómica post-E/S, verificación estricta de `session_uuid`, plazos monotónicos con `Instant` y mapeo nativo de `ErrorKind`. |
| **TCP Sockets & Transport** | `tests/test_tcp_transport.rs` | 4 | **100% PASS** | Framing sobre streams TCP reales, contención de Allocation Bomb y serialización/deserialización en bucle. |
| **MCP Shield Bridge** | `tests/test_mcp_bridge.rs` | 7 | **100% PASS** | Mapeo estricto de llamadas MCP JSON-RPC (`tools/call` -> `ProposeIntent`, `tools/list` -> `DiscoverSkill`), respuestas (`AttestResult`/`RejectPolicy`), rechazo de métodos desconocidos (`UnsupportedMethod`) y derivación determinista de `session_uuid` con FNV-1a. |
| **MCP Proxy E2E Enforcement** | `tests/test_mcp_proxy_e2e.rs` | 1 | **100% PASS** | Proxy TCP real que intercepta MCP JSON-RPC, encapsula en I-PDU y evalúa el firewall MSAC. **Demostración de No-Ejecución**: un contador atómico en el Mock Tool Server verifica que ante bloqueos (taint/prompt injection) la herramienta física jamás recibe tráfico. |
| **Protocol Handshake** | `tests/test_handshake_simulation.rs` | 1 | **100% PASS** | Negociación completa del 3-Way Intent Handshake entre Cliente y Proveedor con auditoría en ambos firewalls. |
| **Total General** | **7 Suites de Tests** | **40** | **40 PASADAS** | **0 fallos, 0 errores, 0 ignoradas** |

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
9. **`test_validate_frame_bounds_trailing_bytes`**:
   - Valida la simetría binaria y el rechazo estricto si una trama contiene bytes sobrantes tras el payload declarado (`Err(IpduError::TrailingBytes)`).

---

### 2.2. Filtro de Reglas de Usuario: Cognitive Reference Monitor (`tests/test_firewall_msac.rs`)

Evalúa los 3 pasos atómicos de intercepción obligatoria (*Mandatory Semantic Access Control*) y la contención de memoria:

#### Paso 1: Taint Tracking Monotónico (Sub-microsegundo)
1. **`test_msac_step1_clean_process_allowed`**:
   - Un proceso sin contaminar emitiendo un intent legítimo recibe `Verdict::Allow`.
2. **`test_msac_step1_medical_taint_blocks_external_egress`**:
   - Un proceso cuyo contexto leyó datos médicos (`TaintTag::MEDICAL_PII`) e intenta comunicarse hacia interfaces de red externas es bloqueado en seco con `Verdict::Drop` y código `-EPERM_COGNITIVE_POLICY` antes de evaluar el resto de la cabecera.
3. **`test_taint_source_descriptor_traceability_in_audit_record`**:
   - Verifica que el registro forense (`AuditRecord`) preserve con exactitud el descriptor de origen de la contaminación (ej. `"read:/var/lib/patient_history.db"`).

#### Paso 2: Reglas Soberanas de Usuario y Cabecera ($O(1)$)
4. **`test_msac_step2_budget_exceeded_drop`**:
   - Un paquete con `MAX_BUDGET_CAP` superior al límite soberano del usuario es descartado con `-EPERM_BUDGET_EXCEEDED`.
5. **`test_msac_step2_sandbox_required_drop`**:
   - Un paquete con `AUTONOMY_TIER >= 2` que no incluye el flag `REQUIRE_SANDBOXED_INFERENCE` es bloqueado con `-EPERM_SANDBOX_REQUIRED`.
6. **`test_msac_step2_forbidden_skill_drop`**:
   - Una petición dirigida a un `SKILL_NAMESPACE_HASH` en lista negra es bloqueada con `-EPERM_FORBIDDEN_SKILL`.

#### Paso 3: Heuristic Gatekeeper (DLP y Anti-Injection)
7. **`test_msac_step3_gatekeeper_credit_card_drop`**:
   - Detecta números de tarjeta de crédito (Visa/Mastercard) en el payload semántico validados con el algoritmo de Luhn y descarta con `-EPERM_SEMANTIC_EXFILTRATION`.
8. **`test_msac_step3_gatekeeper_prompt_injection_drop`**:
   - Detecta intentos de subversión cognitiva (*Cross-Agent Prompt Injection*) como `"ignore previous instructions"` y descarta con `-EPERM_PROMPT_INJECTION`.

#### Resiliencia Operativa y Validación de Políticas
9. **`test_firewall_audit_log_ring_buffer_bounded`**:
   - Verifica que el Ring Buffer (`VecDeque`) descarte entradas antiguas en $O(1)$ manteniendo su cota fija (`max_audit_entries`), previniendo agotamiento de memoria.
10. **`test_default_msac_conf_file_is_valid`**:
    - Valida que el archivo `policies/default_msac.conf` sea sintácticamente correcto.
11. **`test_policy_from_conf_str_valid_and_roundtrip`**:
    - Comprueba el parseo y roundtrip de cadenas de configuración válidas.
12. **`test_policy_from_conf_str_malformed_syntax_rejection`**:
    - Comprueba el rechazo de sintaxis malformada sin `=` o con claves vacías.
13. **`test_policy_from_conf_str_duplicate_keys_and_sandbox_tier_limits`**:
    - Comprueba el rechazo de claves escalares duplicadas y valores de `require_sandbox_above_tier > 63`.

---

### 2.3. Sesión de Transporte y Máquina de Estados (`tests/test_transport_fsm.rs`)

1. **`test_fsm_rejects_out_of_sequence_commit_in_idle`**:
   - Comprueba que enviar `CommitContract` desde `Idle` resulte en rechazo por transición inválida.
2. **`test_fsm_happy_path_handshake_transitions_bidirectional`**:
   - Ejecuta un handshake bidireccional completo entre dos sesiones vinculadas mediante un pipe dúplex: `Initiator` vs `Responder`.
3. **`test_fsm_rejects_session_uuid_mismatch`**:
   - Valida que paquetes dirigidos a un `session_uuid` diferente al activo sean rechazados.
4. **`test_fsm_clean_disconnect_termination`**:
   - Comprueba el cierre ordenado de sesión.
5. **`test_fsm_tcp_read_timeout_expiration`**:
   - Comprueba que la expiración del plazo monotónico (`deadline_ttl_ms`) culmine en `IpduError::DeadlineExpired` y estado `Terminated(Timeout)`.

---

### 2.4. Adaptador y Proxy MCP E2E (`tests/test_mcp_bridge.rs` y `tests/test_mcp_proxy_e2e.rs`)

1. **`test_fnv1a_hash_determinism`**:
   - Valida el cálculo determinista sin asignación de `skill_namespace_hash` mediante FNV-1a.
2. **`test_mcp_tool_call_encapsulation_and_decapsulation`**:
   - Valida el encapsulamiento de `tools/call` hacia `Performative::ProposeIntent` y derivación de `session_uuid` a partir de `id`.
3. **`test_mcp_response_encapsulation_and_decapsulation`**:
   - Valida el encapsulamiento de respuestas exitosas hacia `Performative::AttestResult`.
4. **`test_mcp_response_error_encapsulation`**:
   - Valida el mapeo de errores JSON-RPC hacia `Performative::RejectPolicy`.
5. **`test_mcp_unsupported_method_rejection`**:
   - Valida que métodos JSON-RPC ajenos devuelvan `Err(McpBridgeError::UnsupportedMethod)`.
6. **`test_mcp_inspect_and_wrap_prompt_injection_drop`**:
   - Valida el bloqueo de prompt injection al envolver llamadas MCP.
7. **`test_mcp_inspect_and_wrap_taint_drop`**:
   - Valida el bloqueo por tinte activo al envolver llamadas MCP.
8. **`test_mcp_proxy_e2e_real_enforcement`**:
   - Levanta un Mock MCP Tool Server sobre TCP con un contador atómico `executions`.
   - Levanta un `IlpSidecarProxy` que intercepta llamadas MCP, evalúa el firewall MSAC y solo reenvía con `Verdict::Allow`.
   - **Prueba de No-Ejecución**: ante llamadas bloqueadas (tinte médico o prompt injection), el contador del Mock Tool Server no se incrementa, garantizando que el servidor físico jamás ejecutó la herramienta.

---

### 2.5. Transporte TCP y Handshake (`tests/test_tcp_transport.rs` y `tests/test_handshake_simulation.rs`)

1. **`test_tcp_transport_roundtrip_handshake`**: Handshake I-PDU sobre sockets TCP de loopback reales.
2. **`test_tcp_transport_empty_payload`**: Soporte de paquetes con payload vacío (0 bytes).
3. **`test_tcp_transport_clean_disconnect`**: Manejo de desconexión sin panics.
4. **`test_tcp_transport_allocation_bomb_rejection`**: Rechazo en el socket de tramas que declaran más de 64 KB sin asignar memoria.
5. **`test_full_3way_intent_handshake`**: Simulación multi-turno completa entre dos agentes con auditoría cruzada en ambos firewalls.

---

## 3. Instrucciones de Reproducción

```bash
cargo test --all-targets --all-features
```

Salida esperada:
```text
test result: ok. 40 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
