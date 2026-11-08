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
cargo build

# Ejecutar la suite completa de tests unitarios y de integración (54 tests)
cargo test --all-targets --all-features

# Comprobar análisis estático sin advertencias
cargo clippy --all-targets --all-features -- -D warnings
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

Para impedir la inyección directa de tramas I-PDU espurias contra el Gateway, ambos daemons (`ilp_mcp_sidecar` e `ilp_mcp_gateway`) soportan autenticación de integridad basada en SipHash-2-4 con clave de 128 bits (`--psk <HEX_KEY>`):
- El Sidecar firma criptográficamente los primeros 28 bytes de la cabecera canónica + payload e inserta el MAC resultante en el campo `user_rule_sig_hash` de la cabecera.
- El Gateway verifica la firma antes de procesar o despachar cualquier llamada al servidor de herramientas. Si la clave no coincide o la trama fue alterada, el Gateway responde con `Performative::RejectPolicy` y código JSON-RPC `-32001`.
- **Guardrail de red no-loopback:** El enlace a interfaces de red externas (`0.0.0.0` o IPs públicas) está bloqueado por defecto; requiere la presencia explícita de `--allow-non-loopback` y una clave `--psk`.

#### 3. Daemons de Producción Autónomos (`ilp_mcp_sidecar` y `ilp_mcp_gateway`)

El proyecto provee dos binarios de línea de comandos independientes:

- **`ilp_mcp_sidecar`**: Intercepta tráfico JSON-RPC del agente, audita con MSAC (Zero-Connect: jamás abre TCP al gateway si la política rechaza), auto-mancha dinámicamente el proceso ante respuestas con datos sensibles (`DLP Ingress`), firma tramas con PSK y maneja concurrencia atómica (CAS) sin condiciones de carrera.
- **`ilp_mcp_gateway`**: Recibe paquetes binarios I-PDU del sidecar sobre `IlpStream`, verifica la autenticación PSK, despacha JSON-RPC al backend de herramientas MCP y propaga errores estructurados (`-32002`) si el backend está inalcanzable.

```bash
# Validar sintaxis y configuración sin iniciar los servidores (--check-config)
cargo run --bin ilp_mcp_sidecar --features mcp -- --check-config --policy policies/default_msac.conf
cargo run --bin ilp_mcp_gateway --features mcp -- --check-config --psk 00112233445566778899aabbccddeeff
```

#### 4. Guía de Despliegue en 3 Terminales (Quickstart)

Sigue estos pasos para desplegar la arquitectura completa en terminales independientes:

```bash
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
    --backend 127.0.0.1:8080 \
    --psk 00112233445566778899aabbccddeeff

# ------------------------------------------------------------------------------
# TERMINAL 3: ILP MCP Sidecar Daemon (recibe JSON-RPC en 9001 -> reenvía a 9002)
# ------------------------------------------------------------------------------
cargo run --bin ilp_mcp_sidecar --features mcp -- \
    --listen 127.0.0.1:9001 \
    --gateway 127.0.0.1:9002 \
    --policy policies/default_msac.conf \
    --psk 00112233445566778899aabbccddeeff \
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
