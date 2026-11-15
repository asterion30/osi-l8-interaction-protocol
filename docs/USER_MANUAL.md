# Manual de Usuario y Guía de Implementación: ILP-Core & Cognitive Firewall (MSAC)

Este manual proporciona una guía integral para entender, compilar, ejecutar y trasladar el **Firewall Cognitivo de Capa 8 (MSAC)** y el **Protocolo de Interacción Agéntica (ILP / RFC-ILP-2026)** a diversos entornos de producción e infraestructura.

---

## 1. Visión General de la Arquitectura

`ilp-core` implementa un protocolo binario determinista de Capa 8 y un motor de control de acceso semántico obligatorio (**Mandatory Semantic Access Control - MSAC**):

```
+-------------------------------------------------------------------------+
|                  APLICACIÓN AGÉNTICA (LLM / Agent Runtime)              |
+-------------------------------------------------------------------------+
                                    |
            (Llamada de intención / Herramienta / Inferencia)
                                    v
+-------------------------------------------------------------------------+
|       MSAC COGNITIVE FIREWALL (Sidecar Egress Proxy en Rust)            |
|                                                                         |
|  [Paso 1: Taint Tracking] -> Auditoría de tinte (Medical/PII/Creds)     |
|  [Paso 2: Reglas Declarativas] -> Presupuesto, TTL, Autonomía, Sandbox |
|  [Paso 3: HeuristicGatekeeper] -> Detección de inyecciones y exfiltración |
|                                                                         |
|         Veredicto: DROP (0 ns red)  ó  ALLOW (< 5 µs)                   |
+-------------------------------------------------------------------------+
                                    | (Si es ALLOW)
                                    v
+-------------------------------------------------------------------------+
|               TRANSPORTE BINARIO ILP (`IlpStream` sobre TCP)            |
|       [36B Cabecera Canónica] + [4B Length Prefix] + [Payload <=64KB]   |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|              RED FÍSICA (TLS / Sockets TCP / Unix Domain Sockets)       |
+-------------------------------------------------------------------------+
```

### Características Clave
- **Sub-microsegundo**: Inspección y validación de políticas en nanosegundos frente a los milisegundos que toma parsear JSON o llamar a un modelo guardián por HTTP.
- **Cero dependencias externas**: El núcleo (`ilp-core`) no requiere Tokio ni crates pesados; funciona exclusivamente con `std`.
- **Blindaje en memoria (Allocation Bomb Defense)**: Cota estricta de 64 KB por trama que imposibilita ataques de denegación de servicio por agotamiento de RAM (OOM).

---

## 2. Inicio Rápido (Quickstart)

### Requisitos
- Rust toolchain estable (versión 1.70+ con edición 2021).
- Cargo.

### Compilación y Pruebas
```bash
# Compilar la biblioteca y binarios
cargo build --locked

# Ejecutar la suite completa de tests unitarios y de integración (81 tests)
cargo test --locked --all-targets --all-features

# Auditar y verificar el conteo formal de pruebas
./scripts/verify_test_count.sh

# Comprobar análisis estático sin advertencias (MSRV 1.70.0 y Stable)
cargo clippy --locked --all-targets --all-features -- -D warnings
```

### Ejecutar la Demostración de Red en Vivo (Multi-Agente)
El ejemplo `live_agent_proxy` levanta dos agentes independientes comunicándose por sockets TCP reales (`127.0.0.1:8088`), donde el agente cliente pasa obligatoriamente por el Firewall MSAC antes de emitir ningún byte a la red:

```bash
cargo run --example live_agent_proxy
```

Verás una salida en consola con marcas de tiempo en microsegundos ($\mu s$) y nanosegundos ($ns$):
1. **Escenario 1 (Handshake Exitoso)**: Negociación de 3 vías (`DISCOVER_SKILL` -> `PROPOSE_INTENT` -> `COUNTER_OFFER` -> `COMMIT_CONTRACT`).
2. **Escenario 2 (Bloqueo en el Borde - Taint Drop)**: Al adquirir tinte médico (`TaintTag::MEDICAL_PII`), el firewall descarta el paquete en menos de 500 ns sin que ningún byte toque el socket TCP.
3. **Escenario 3 (Bloqueo por Inyección Adversaria)**: Intento de evasión detectado por el HeuristicGatekeeper en el payload semántico.
4. **Resumen Forense**: Registro inmutable de eventos en el Ring Buffer de auditoría.

---

## 3. Guía de Integración Paso a Paso en Código Rust

### Paso 1: Configurar la Política Soberana del Usuario (`UserGovernancePolicy`)
Puedes definirla programáticamente o cargarla sin recompilar desde un archivo de configuración `.conf`:

```rust
use ilp_core::governance::UserGovernancePolicy;

// Opción A: Carga declarativa desde archivo .conf (Zero-Dependencies)
let conf_str = std::fs::read_to_string("policies/default_msac.conf")
    .expect("Lectura de archivo de configuración");
let policy = UserGovernancePolicy::from_conf_str(&conf_str)
    .expect("Parse de políticas");

// Opción B: Construcción programática
let mut custom_policy = UserGovernancePolicy::default();
custom_policy.max_budget_cap = 50_000;
custom_policy.deny_external_egress_if_tainted = true;
custom_policy.require_sandbox_above_tier = 2;
```

### Paso 2: Inicializar el Firewall Cognitivo y el Contexto de Tinte con Trazabilidad
```rust
use ilp_core::governance::{CognitiveFirewall, ProcessTaintContext, TaintTag};

let mut firewall = CognitiveFirewall::new(policy);
let mut taint_context = ProcessTaintContext::new(1001, "Agente-Analista", true);

// Si el agente interactúa con datos confidenciales, se registra el origen exacto:
taint_context.apply_taint(
    TaintTag::MEDICAL_PII,
    "read:/var/lib/hospital/oncology_records.db"
);
```

### Paso 3: Inspeccionar y Transmitir con la FSM de Transporte (`IlpSession`)
```rust
use ilp_core::governance::Verdict;
use ilp_core::ipdu::flags::CognitivePolicyFlags;
use ilp_core::ipdu::packet::IpduPacket;
use ilp_core::transport::{IlpSession, IlpStream, SessionRole};
use std::net::TcpStream;

// Establecer conexión de red y sesión de Capa 8 especificando el rol FSM
let stream = IlpStream::connect("127.0.0.1:8088").expect("Conexión TCP");
let mut session = IlpSession::new(stream, SessionRole::Initiator);

// Construir paquete inicial de descubrimiento o propuesta de intención
let packet = IpduPacket::discover_skill(
    0xCAFE_BABE,
    0x1234_5678_9ABC_DEF0,
    CognitivePolicyFlags::EMPTY,
    "oncology_diagnostic_query",
);

// Inspección obligatoria previa al socket
let decision = firewall.inspect_egress(&taint_context, &packet);

if decision.verdict == Verdict::Allow {
    // IlpSession valida automáticamente la máquina de estados y el session_uuid
    session.send_packet(&packet).expect("Envío conforme a la FSM");

    // Acceso seguro y de solo lectura a la cabecera y el payload:
    let _session_uuid = packet.header().session_uuid;
    let _payload = packet.payload();
} else {
    eprintln!("⛔ Paquete bloqueado por el firewall: {:?}", decision.reason);
    // Ningún byte tocó el socket de red
}
```

---

## 4. Traslado del Firewall a Diferentes Entornos

### Entorno A: Kubernetes Pod (Patrón Sidecar)
En Kubernetes, se ejecuta el agente de IA (en Python, Node.js o Go) y el demonio `ilp-proxy` dentro del mismo Pod compartiendo `localhost`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secured-ai-agent
spec:
  containers:
    - name: agent-app
      image: my-company/customer-service-agent:latest
      env:
        - name: ILP_PROXY_HOST
          value: "127.0.0.1"
        - name: ILP_PROXY_PORT
          value: "8088"
    - name: ilp-cognitive-firewall
      image: asterion/ilp-firewall:v0.2
      ports:
        - containerPort: 8088
```
- **Ventaja**: El agente no puede emitir tráfico directo a internet; todas sus peticiones de red deben pasar obligatoriamente por el sidecar local.

### Entorno B: Daemon Local Linux con Unix Domain Sockets (UDS)
Para servidores o estaciones de trabajo donde no se quieren abrir puertos de red TCP:
1. `ilp-daemon` crea un socket local seguro en `/var/run/ilp/msac.sock` con permisos `0600`.
2. Los agentes locales se conectan mediante `std::os::unix::net::UnixStream`.
3. `IlpStream` envuelve `UnixStream` directamente sin cambios de código, garantizando aislamiento estricto entre usuarios del sistema.

### Entorno C: Filtro WebAssembly (WASM) en Envoy / Istio / Kong
`ilp-core` no contiene llamadas bloqueantes al sistema operativo en su motor de filtrado:
- Se compila con `cargo build --target wasm32-wasi --release`.
- Se registra como un filtro `HttpFilter` o `NetworkFilter` en Envoy Proxy.
- Permite que las arquitecturas de microservicios existentes apliquen políticas de gobernanza agéntica en el API Gateway sin desplegar software nuevo.

### Entorno D: Middleware FFI para Ecosistemas Python (LangChain / AutoGen / CrewAI)
Puedes exponer la función de filtrado mediante `extern "C"` o con `PyO3`:
```python
from ilp_guard import CognitiveFirewall, TaintTag

firewall = CognitiveFirewall.from_config("governance.json")

def agent_egress_hook(tool_call):
    decision = firewall.inspect_tool_call(tool_call)
    if not decision.is_allowed():
        raise PermissionError(f"MSAC Block: {decision.reason}")
    return execute_remote_api(tool_call)
```

### Entorno E: Adaptador y Proxy Sidecar para Model Context Protocol (MCP)
El módulo `ilp_core::bridge` permite proteger llamadas MCP JSON-RPC (`tools/call`, `prompts/get`) activando el feature opcional `mcp`.

#### 1. Modelo de Amenazas y Confinamiento de Red Obligatorio (Non-Evasible Enforcement)

> [!IMPORTANT]
> **Naturaleza del Proxy Sidecar:** El `ilp_mcp_sidecar` opera como un **proxy a nivel de aplicación**. Un agente de IA cooperativo configurará su cliente MCP para conectarse a `127.0.0.1:9001` (puerto del sidecar). Sin embargo, un agente malicioso, comprometido o no cooperativo podría intentar evadir el firewall conectándose directamente al gateway o emitiendo paquetes hacia la red externa.

Para garantizar un **control de acceso obligatorio e ineludible (Non-Evasible Enforcement)** en producción, el entorno debe imponer aislamiento a nivel de kernel mediante Linux Network Namespaces, Docker Containers o reglas de cortafuegos por UID (`iptables` / `nftables`):

```bash
# 1. Crear usuario del sistema dedicado exclusivamente al daemon sidecar
useradd -r -s /bin/false ilp-sidecar

# 2. Permitir ÚNICAMENTE al usuario del sidecar tráfico saliente hacia el Gateway ILP (puerto 9002)
iptables -A OUTPUT -m owner --uid-owner ilp-sidecar -d 127.0.0.1 -p tcp --dport 9002 -j ACCEPT

# 3. Restringir la salida del usuario del agente (agent-user) exclusivamente al puerto ingress del sidecar (9001)
iptables -A OUTPUT -m owner --uid-owner agent-user -d 127.0.0.1 -p tcp --dport 9001 -j ACCEPT

# 4. Bloquear cualquier otra conexión TCP saliente del agente (impidiendo evasión directa)
iptables -A OUTPUT -m owner --uid-owner agent-user -j DROP
```

En entornos con **Docker / Kubernetes**, se confina el runtime del agente en una red interna privada (`--internal` o NetworkPolicy sin egress directo) conectada exclusivamente al contenedor del sidecar.

#### 2. Autenticación Criptográfica de Trama con Clave Pre-compartida (PSK / SipHash-2-4)

Para impedir la inyección directa de tramas I-PDU espurias contra el Gateway, ambos daemons (`ilp_mcp_sidecar` e `ilp_mcp_gateway`) soportan autenticación de integridad basada en SipHash-2-4 con clave de 128 bits:
- **Carga Segura de Clave (Prioridad de Carga)**:
  1. `--psk-file <PATH>`: Carga la clave desde un archivo protegido con permisos estrictos de Unix (`0600` o `0400`, accesible solo por el propietario). Rechaza explícitamente enlaces simbólicos (*symlinks*) y valida los permisos en el descriptor abierto (`fstat`) libre de TOCTOU con lectura acotada a 256 bytes.
  2. `ILP_PSK_HEX`: Variable de entorno con la clave en hexadecimal (32 caracteres).
  3. `--psk <HEX_KEY>`: [DEPRECATED / TEST-ONLY] Argumento en línea de comandos (emite advertencia de seguridad debido a su visibilidad en `/proc` y `ps`).
- **Cifrado de Flujo en Tránsito ChaCha20 (RFC 8439) y Encrypt-then-MAC**:
  - Implementado en Rust puro (`std`-only, 0 dependencias externas).
  - El Sidecar cifra el payload JSON-RPC con ChaCha20, activa el flag `CognitivePolicyFlags::ENCRYPTED_PAYLOAD` en la cabecera canónica I-PDU, y calcula el MAC SipHash-2-4 sobre la cabecera + ciphertext (*Encrypt-then-MAC*).
  - La clave ChaCha20 se deriva vía KDF determinista desde la PSK (`"ILP-ChaCha20-Payload-Key-Derivation"`).
  - Los nonces se derivan por sesión con separación estricta de dominios: bit 63 en `0` para peticiones (`is_response = false`), bit 63 en `1` para respuestas (`is_response = true`), garantizando que jamás se reutilice un nonce con la misma clave.
  - Habilitado por defecto (`--encrypt-payload`). Puede desactivarse explícitamente para pruebas con `--no-encrypt-payload`.
- **Rotación de Claves en Caliente sin Caídas (Zero-Downtime Dual-PSK)**:
  - El Gateway admite una clave previa (`--psk-previous-file <PATH>`, `--psk-previous <HEX>` o `ILP_PSK_PREVIOUS_HEX`).
  - Durante ventanas de migración de credenciales, el Gateway acepta tramas firmadas/cifradas con la clave primaria O con la clave anterior, incrementando la métrica atómica `key_rotations_accepted`.
  - La respuesta se cifra y autentica con la misma clave con la que la petición fue verificada, eliminando tiempos de inactividad durante despliegues progresivos de Sidecars.
- **Volcado Forense Estructurado JSONL para SIEM (`--audit-log <PATH>`)**:
  - Tanto `ilp_mcp_sidecar` como `ilp_mcp_gateway` permiten exportar cada evento de auditoría en tiempo real en formato JSONL delimitado por saltos de línea (`\n`), listo para ingesta por Wazuh, ElasticSearch/Logstash o Splunk.
- **Invariante Verify-Then-Parse**: El Gateway recibe la trama cruda y valida el MAC antes de invocar cualquier deserializador JSON-RPC. Si la firma es inválida, se devuelve de inmediato `Performative::RejectPolicy` con código `-32001` sin procesar el contenido de la carga útil.
- **Protección Anti-Replay Fail-Closed (`ReplayGuard`)**: El Gateway mantiene un registro acotado de `session_uuid` observados con ventana temporal de 60 segundos y capacidad máxima de 4096 entradas (el `session_uuid` es único por dominio de clave PSK e instancia de Gateway). Cualquier trama retransmitida con UUID duplicado es descartada con error `-32003` ("Replay attack detected"). Bajo saturación de la tabla sin entradas expiradas, opera bajo política **Fail-Closed**: rechaza nuevas conexiones con error `-32003` ("Gateway replay protection table saturated; try again later") sin desalojar jamás entradas vigentes.
- **Aislamiento de Tinte por Conexión**: Cada cliente que se conecta al Sidecar opera sobre una copia aislada del contexto de tinte. Los datos sensibles detectados en respuestas de herramientas o claims explícitos solo afectan a esa conexión específica, garantizando que un cliente manchado no contamine a otros clientes.
- **Control de Claims de Cliente (`--trust-client-claims`)**: Por defecto (`false`), los daemons descartan claims `_ilp_taint_claim` no autenticados enviados por clientes. Requiere la bandera explícita `--trust-client-claims` para habilitar el auto-etiquetado voluntario por parte del cliente.
- **Guardrail de red no-loopback:** El enlace a interfaces de red externas (`0.0.0.0` o IPs públicas) está bloqueado por defecto; requiere la presencia explícita de `--allow-non-loopback` y una clave pre-compartida válida.

#### 3. Daemons de Producción Autónomos (`ilp_mcp_sidecar` y `ilp_mcp_gateway`)

El proyecto provee dos binarios de línea de comandos independientes:

- **`ilp_mcp_sidecar`**: Intercepta tráfico JSON-RPC del agente, audita con MSAC (Zero-Connect: jamás abre TCP al gateway si la política rechaza), auto-mancha dinámicamente el proceso ante respuestas con datos sensibles (`DLP Ingress`), cifra payloads con ChaCha20 (RFC 8439), firma tramas con PSK SipHash-2-4 y maneja concurrencia atómica (CAS) sin condiciones de carrera. Soporta `--audit-log <PATH>`.
- **`ilp_mcp_gateway`**: Recibe paquetes binarios I-PDU del sidecar sobre `IlpStream`, ejecuta Verify-Then-Parse con soporte Dual-PSK, descifra el payload ChaCha20, filtra con anti-replay fail-closed, despacha JSON-RPC al backend de herramientas MCP y propaga errores estructurados (`-32002`) si el backend está inalcanzable. Soporta `--audit-log <PATH>`.

```bash
# Validar sintaxis y configuración sin iniciar los servidores (--check-config)
cargo run --bin ilp_mcp_sidecar --features mcp -- --check-config --policy policies/default_msac.conf
ILP_PSK_HEX="00112233445566778899aabbccddeeff" cargo run --bin ilp_mcp_gateway --features mcp -- --check-config
```

#### 4. Guía de Despliegue en 3 Terminales (Quickstart)

Sigue estos pasos para desplegar la arquitectura completa en terminales independientes:

```bash
# Exportar la clave pre-compartida segura en el entorno de los daemons
export ILP_PSK_HEX="00112233445566778899aabbccddeeff"

# ------------------------------------------------------------------------------
# TERMINAL 1: Servidor de Herramientas MCP Backend (ejemplo de escucha en 8080)
# ------------------------------------------------------------------------------
# Inicia tu servidor MCP estándar (o un mock en Python / Node.js escuchando en 127.0.0.1:8080)
python3 -m http.server 8080   # o tu servidor MCP real: npx -y @modelcontextprotocol/server-everything

# ------------------------------------------------------------------------------
# TERMINAL 2: ILP MCP Gateway Daemon (recibe I-PDU en 9002 -> despacha a 8080)
# ------------------------------------------------------------------------------
cargo run --bin ilp_mcp_gateway --features mcp -- \
    --listen 127.0.0.1:9002 \
    --backend 127.0.0.1:8080

# ------------------------------------------------------------------------------
# TERMINAL 3: ILP MCP Sidecar Daemon (recibe JSON-RPC en 9001 -> reenvía a 9002)
# ------------------------------------------------------------------------------
cargo run --bin ilp_mcp_sidecar --features mcp -- \
    --listen 127.0.0.1:9001 \
    --gateway 127.0.0.1:9002 \
    --policy policies/default_msac.conf \
    --initial-taint MedicalPii,Credentials

# ------------------------------------------------------------------------------
# TERMINAL 4: Agente / Cliente MCP (Prueba interactiva)
# ------------------------------------------------------------------------------
# El agente se conecta al puerto del Sidecar (9001) como si fuera el servidor MCP:
echo '{"jsonrpc":"2.0","id":"req-01","method":"tools/call","params":{"name":"query_records","arguments":{}}}' | nc 127.0.0.1 9001
```

#### 5. Servidores Programáticos en Rust (`McpSidecarServer` y `McpGatewayServer`)
```rust
use ilp_core::bridge::{McpGatewayServer, McpSidecarServer, SidecarConfig};

let config = SidecarConfig {
    psk: Some([0x42; 16]), // Clave de 128 bits
    ..Default::default()
};

// Gateway ILP: Recibe paquetes binarios I-PDU y despacha JSON-RPC al servidor de herramientas local
let gateway = McpGatewayServer::start("127.0.0.1:9002", "127.0.0.1:8080".to_string(), config.clone())?;

// Sidecar MCP: Intercepta JSON-RPC, audita con MSAC (Zero-Connect) y reenvía tramas binarias autenticadas
let sidecar = McpSidecarServer::start("127.0.0.1:9001", gateway.addr.clone(), firewall, taint_context, config)?;
```

#### 6. Demostración Interactiva del Escudo MCP
Para probar el demo interactivo:
```bash
cargo run --example mcp_shield_demo --features mcp
```

### Entorno F: Medición de Latencia y Micro-Benchmarks
Para reproducir las métricas de rendimiento en tu propia infraestructura sobre 100,000 iteraciones:
```bash
cargo run --release --example benchmark_latency
```

---

## 5. Códigos de Error de Denegación (Cognitive Error Codes)

| Código | Significado | Causa Típica |
| :--- | :--- | :--- |
| `EPERM_COGNITIVE_POLICY` | Violación de Tinte / DLP | Proceso marcado con PII médica, financiera o credenciales intentando salir a internet público. |
| `EPERM_BUDGET_EXCEEDED` | Límite de Gasto Superado | La petición declara más tokens/presupuesto del autorizado por la política soberana del usuario. |
| `EPERM_AUTONOMY_EXCEEDED` | Techo de Autonomía Violado | El agente solicita actuar en un Tier de autonomía superior al concedido. |
| `EPERM_SANDBOX_REQUIRED` | Aislamiento Obligatorio | Se requiere el flag `REQUIRE_SANDBOXED_INFERENCE` y el agente no lo proporcionó. |
| `EPERM_PROMPT_INJECTION` | Inyección Adversaria | El payload contiene patrones de jailbreak, evasión o suplantación de identidad instruccional. |
| `EPERM_SEMANTIC_EXFILTRATION` | Fuga de Datos en Carga Útil | El payload contiene números de tarjeta de crédito, números de seguridad social o secretos API. |

---

## 6. Métodos MCP Soportados y Correspondencia con Performativas I-PDU

El puente `McpBridge` traduce y encapsula el subconjunto oficial de métodos JSON-RPC del Model Context Protocol (MCP 2024-11-05) mapeándolos a performativas formales de Capa 8:

| Método MCP JSON-RPC | Performativa I-PDU Capa 8 | Semántica Operativa y Control Cognitivo |
| :--- | :--- | :--- |
| `initialize` | `Performative::DiscoverSkill` | Negociación inicial de versión del protocolo y capacidades. |
| `notifications/initialized` | `Performative::DiscoverSkill` | Confirmación de cliente agéntico listo para procesar intenciones. |
| `ping` | `Performative::DiscoverSkill` | Heartbeat de disponibilidad de conexión y baja sobrecarga. |
| `tools/list` | `Performative::DiscoverSkill` | Inspección del catálogo de herramientas autorizadas según tier. |
| `prompts/list` | `Performative::DiscoverSkill` | Descubrimiento de plantillas de prompts de inferencia disponibles. |
| `resources/list` | `Performative::DiscoverSkill` | Enumeración de URIs de recursos y fuentes expuestas. |
| `tools/call` | `Performative::ProposeIntent` | Invocación de herramienta auditada por MSAC, DLP y Taint Tracking. |
| `resources/read` | `Performative::ProposeIntent` | Lectura de recurso con derivación de hash de URI y control de tinte. |
| `prompts/get` | `Performative::ProposeIntent` | Obtención parametrizada de prompts con validación de inyección instruccional. |

---

## 7. Checklist de Operaciones de Producción y Hardening

Para desplegar la arquitectura de Capa 8 en entornos de misión crítica, seguir este checklist riguroso:

1. **Gestión y Almacenamiento Seguro de Claves PSK**:
   - Asignar permisos estrictos de lectura exclusiva: `chmod 0600` o `chmod 0400` al archivo de clave.
   - Prohibir terminantemente el uso de enlaces simbólicos (`symlink`) y enlaces duros (`hardlink`) para prevenir ataques TOCTOU y accesos compartidos fuera del control del daemon.
   - El daemon valida atómicamente en Linux/POSIX mediante `MetadataExt` que `symlink_metadata().dev() == file.metadata().dev()`, `ino() == ino()` y `nlink() == 1`.

2. **Rotación de Claves sin Tiempo de Inactividad (Zero-Downtime Dual-PSK)**:
   - Configurar en el Gateway la nueva clave como principal (`--psk-file`) y la clave saliente como `--psk-previous-file` (o variables `ILP_PSK_HEX` e `ILP_PSK_PREVIOUS_HEX`).
   - El Gateway acepta instantáneamente ambas claves sin requerir puertos paralelos ni ventanas de indisponibilidad.
   - Migrar progresivamente los Sidecars a la nueva clave.
   - Una vez migrados todos los clientes (verificado mediante la métrica `key_rotations_accepted` en el Gateway), retirar `--psk-previous-file`.

3. **Apagado Ordenado y Drenaje de Conexiones (Graceful Shutdown)**:
   - Configurar `drain_timeout` en `SidecarConfig` y `GatewayConfig` (valor por defecto recomendado: `2000 ms`).
   - Al recibir señales `SIGINT` o `SIGTERM`, invocar `server.shutdown()` para detener la aceptación de nuevos clientes y esperar a que las conexiones activas completen su intercambio I-PDU antes de finalizar el proceso.

4. **Aislamiento de Red y Perímetro Restringido**:
   - Por defecto, los daemons se niegan a escuchar en interfaces no-loopback (`0.0.0.0`) a menos que se especifique explícitamente `--allow-non-loopback` y una clave `--psk-file` válida.
   - El payload viaja cifrado en tránsito de extremo a extremo con ChaCha20 (RFC 8439) y autenticado con SipHash-2-4 (*Encrypt-then-MAC*). Para aislamiento adicional, aislar los daemons mediante topología de red restringida en Docker (`internal: true`) o namespaces de Linux.

5. **Protección Anti-Replay y Política Fail-Closed bajo Carga**:
   - Dimensionar la ventana temporal de `ReplayGuard` (`window_ttl = 60s`, `max_entries = 4096`).
   - Bajo ráfagas extremas que saturen la tabla de memoria, el Gateway aplica política *Fail-Closed*: rechaza solicitudes adicionales con error `-32003` en lugar de expulsar entradas vigentes, preservando la garantía absoluta de no-repetición.

6. **Monitoreo y Auditoría de Tinte en Tiempo Real (SIEM)**:
   - Habilitar el flag `--audit-log /var/log/ilp/audit.jsonl` en los daemons para volcar cada evento forense a un archivo JSONL en streaming.
   - Configurar el agente SIEM (Wazuh, Elastic Filebeat, FluentBit) para monitorizar `/var/log/ilp/audit.jsonl`.
   - Alertar inmediatamente ante eventos con `"decision":"Drop"`, especialmente códigos `EPERM_COGNITIVE_POLICY` (intento de exfiltración de PII o credenciales), `EPERM_PROMPT_INJECTION` y `EPERM_SEMANTIC_EXFILTRATION`.

---

## 8. Infraestructura de Despliegue en Producción (`deploy/`)

El repositorio provee infraestructura lista para producción en el directorio [`deploy/`](../deploy/):

### 1. Contenedor Docker Multi-Stage (`deploy/Dockerfile`)
- Construcción optimizada en 2 etapas: `cargo build --release --locked` sobre toolchain oficial de Rust, copiado a runtime minimalista sobre `debian:bookworm-slim`.
- Usuario sin privilegios dedicado: `UID 10001:GID 10001` (`ilp`), sin acceso `root` ni `sudo`.
- Directorio de auditoría `/var/log/ilp` con permisos exclusivos `0750`.
- Compilación:
  ```bash
  docker build -f deploy/Dockerfile -t ilp-core:latest .
  ```

### 2. Orquestación Segregada (`deploy/docker-compose.isolated.yml`)
Define una topología de tres redes aisladas:
1. `agent_sandbox_net`: Red interna (`internal: true`) sin puerta de enlace hacia internet público. El agente agéntico reside aquí y solo tiene visibilidad hacia el puerto del Sidecar (`127.0.0.1:9001` o IP de red).
2. `ilp_backbone_net`: Red interna punto a punto entre Sidecar y Gateway para el túnel binario I-PDU (cifrado con ChaCha20 y firmado con SipHash-2-4).
3. `tools_backend_net`: Red donde reside el servidor de herramientas MCP backend y el Gateway.
- Carga de secretos PSK mediante Docker Secrets con permisos `0400`.
- Límites de recursos estrictos (`limits: cpus: '1.0'`, `memory: 128M`).

Ejecución:
```bash
# Crear claves secretas de ejemplo
mkdir -p deploy/secrets
openssl rand -hex 16 > deploy/secrets/ilp_psk.key
chmod 0400 deploy/secrets/ilp_psk.key

docker compose -f deploy/docker-compose.isolated.yml up -d
```

### 3. Servicios Hardened para Linux (`deploy/systemd/`)
Para despliegues nativos sobre Linux sin contenedores, se incluyen unidades de servicio con aislamiento estricto del kernel:
- `deploy/systemd/ilp-mcp-sidecar.service`
- `deploy/systemd/ilp-mcp-gateway.service`

Directivas de endurecimiento aplicadas:
- `User=ilp`, `Group=ilp`
- `ProtectSystem=strict`, `ProtectHome=true`
- `NoNewPrivileges=true`, `PrivateTmp=true`, `PrivateDevices=true`
- `ProtectKernelTunables=true`, `ProtectKernelModules=true`, `ProtectControlGroups=true`
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
- `CapabilityBoundingSet=` (cero capacidades Linux permitidas)
- `MemoryMax=256M`, `TasksMax=64`

### 4. Formato de Eventos Forenses SIEM (JSON Lines)
Cada registro escrito en `--audit-log` genera una línea JSON válida:
```json
{"timestamp_epoch_secs":1731638400,"component":"Sidecar","decision":"Drop","reason":"EpermSemanticExfiltration","session_uuid":84920481239,"taint_bitmask":4,"taint_labels":["FinancialPii"],"taint_sources":["file:/data/payments.csv"],"payload_len":184}
```
Listo para ser parseado e indexado automáticamente por Wazuh, Datadog o Elasticsearch sin necesidad de expresiones regulares complejas.

