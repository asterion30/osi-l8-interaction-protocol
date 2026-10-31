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
|  [Paso 3: SLM Gatekeeper] -> Detección de inyecciones y exfiltración   |
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

# Ejecutar la suite completa de tests unitarios y de integración (21 tests)
cargo test

# Comprobar análisis estático sin advertencias
cargo clippy --all-targets -- -D warnings
```

### Ejecutar la Demostración de Red en Vivo (Multi-Agente)
El ejemplo `live_agent_proxy` levanta dos agentes independientes comunicándose por sockets TCP reales (`127.0.0.1:8088`), donde el agente cliente pasa obligatoriamente por el Firewall MSAC antes de emitir ningún byte a la red:

```bash
cargo run --example live_agent_proxy
```

Verás una salida en consola con marcas de tiempo en microsegundos ($\mu s$) y nanosegundos ($ns$):
1. **Escenario 1 (Handshake Exitoso)**: Negociación de 3 vías (`DISCOVER_SKILL` -> `PROPOSE_INTENT` -> `COUNTER_OFFER` -> `COMMIT_CONTRACT`).
2. **Escenario 2 (Bloqueo en el Borde - Taint Drop)**: Al adquirir tinte médico (`TaintTag::MEDICAL_PII`), el firewall descarta el paquete en menos de 500 ns sin que ningún byte toque el socket TCP.
3. **Escenario 3 (Bloqueo por Inyección Adversaria)**: Intento de evasión detectado por el SLM Gatekeeper en el payload semántico.
4. **Resumen Forense**: Registro inmutable de eventos en el Ring Buffer de auditoría.

---

## 3. Guía de Integración Paso a Paso en Código Rust

### Paso 1: Configurar la Política Soberana del Usuario (`UserGovernancePolicy`)
```rust
use ilp_core::governance::UserGovernancePolicy;

let mut policy = UserGovernancePolicy::default();
policy.max_budget_cap = 500; // Máximo 500 tokens/créditos por sesión
policy.deny_external_egress_if_tainted = true; // Prohibir salida si hay PII
policy.require_sandbox_above_tier = 2; // Exigir sandbox para autonomía media/alta
```

### Paso 2: Inicializar el Firewall Cognitivo y el Contexto de Tinte
```rust
use ilp_core::governance::{CognitiveFirewall, ProcessTaintContext, TaintTag};

let mut firewall = CognitiveFirewall::new(policy);
let mut taint_context = ProcessTaintContext::new(1001, "Agente-Analista", false);

// Si el agente lee datos médicos clasificados:
taint_context.contaminate_with(TaintTag::MEDICAL_PII);
```

### Paso 3: Inspeccionar Paquetes con el Proxy Egress antes de Enviar
```rust
use ilp_core::governance::Verdict;
use ilp_core::ipdu::IpduPacket;
use ilp_core::transport::IlpStream;
use std::net::TcpStream;

// Establecer conexión de red
let mut stream = IlpStream::connect("127.0.0.1:8088").expect("Conexión TCP");

// Inspección obligatoria previa al socket
let packet = /* construir IpduPacket */;
let decision = firewall.inspect_egress(&taint_context, &packet);

if decision.verdict == Verdict::Allow {
    stream.send_packet(&packet).expect("Envío seguro a la red");
} else {
    eprintln!("⛔ Paquete bloqueado por el firewall: {:?}", decision.reason);
    // Ningún dato fue transmitido
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

### Entorno E: Adaptador para Model Context Protocol (MCP) de Anthropic
En la Fase 2, se integra un proxy adaptador que toma tramas JSON-RPC de MCP (`tools/call`, `prompts/get`), calcula su huella hash y las encapsula en una I-PDU de Capa 8. Esto permite que herramientas estándar de Claude Desktop o Cursor queden protegidas contra prompt injection y fugas de datos sin modificar las herramientas MCP existentes.

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
