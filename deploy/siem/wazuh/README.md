# Integración SIEM Wazuh para Capa 8 (RFC-ILP-2026)

Este directorio contiene las reglas de detección y auditoría forense para **Wazuh SIEM / XDR**, diseñadas para ingerir y correlacionar en tiempo real los registros estructurados en formato **JSONL** emitidos por `ilp_mcp_sidecar` e `ilp_mcp_gateway` a través del flag `--audit-log <RUTA>`.

---

## 1. Configuración del Agente Wazuh (`ossec.conf`)

Para recolectar los eventos emitidos por los daemons de Capa 8 en cada nodo o contenedor, añade el siguiente bloque `<localfile>` al archivo `/var/ossec/etc/ossec.conf` del agente Wazuh:

```xml
<ossec_config>
  <!-- Ingesta de Logs Forenses de Capa 8 ILP -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/capa8/ilp_audit.jsonl</location>
  </localfile>
</ossec_config>
```

> **Nota de Permisos**: Asegúrate de que el usuario `wazuh` tenga permisos de lectura sobre `/var/log/capa8/ilp_audit.jsonl` (modo `0640` o pertenencia al grupo `capa8`).

---

## 2. Instalación de Reglas en el Wazuh Manager

1. Copia el archivo `ilp_rules.xml` al directorio de reglas personalizadas de tu Wazuh Manager:
   ```bash
   cp deploy/siem/wazuh/ilp_rules.xml /var/ossec/etc/rules/ilp_rules.xml
   chown wazuh:wazuh /var/ossec/etc/rules/ilp_rules.xml
   chmod 0660 /var/ossec/etc/rules/ilp_rules.xml
   ```

2. Valida la sintaxis de las reglas en el Manager:
   ```bash
   /var/ossec/bin/wazuh-analysisd -t
   ```

3. Reinicia el servicio Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

---

## 3. Mapeo de Campos JSONL a Campos Indexables

Los daemons de Capa 8 generan eventos JSON delimitados por salto de línea (`\n`) con el esquema de `AuditRecord::to_jsonl_line`. Wazuh decodifica nativamente cada clave JSON bajo el prefijo `data`:

| Campo JSON Emitido | Campo Indexado en Wazuh / OpenSearch | Tipo | Descripción |
| :--- | :--- | :--- | :--- |
| `timestamp_ms` | `data.timestamp_ms` | `date` | Marca de tiempo Unix en milisegundos |
| `component` | `data.component` | `keyword` | Componente emisor (`mcp_sidecar` o `mcp_gateway`) |
| `session_uuid` | `data.session_uuid` | `keyword` | Identificador criptográfico de sesión (anti-colisión) |
| `verdict` | `data.verdict` | `keyword` | Decisión del firewall (`ALLOW` o `DROP`) |
| `error_code` | `data.error_code` | `integer` | Código de error semántico RFC-ILP-2026 |
| `reason` | `data.reason` | `text` | Justificación técnica del veredicto o denegación |
| `active_taints` | `data.active_taints` | `array` | Vector de clasificación de datos activos en el proceso |
| `source_descriptor`| `data.source_descriptor` | `text` | Traza de origen del tinte (ej. `mcp:ingress:tool_response`) |

---

## 4. Matriz de Reglas y Clasificación de Severidad

| ID Regla | Nivel | Clasificación | MITRE ATT&CK | Condición de Activación |
| :--- | :---: | :--- | :--- | :--- |
| **100300** | 3 | Info | - | Cualquier evento de auditoría ILP generado. |
| **100301** | 3 | Info | - | `verdict == "ALLOW"` (petición autorizada). |
| **100310** | 10 | Advertencia | T1059, T1562 | `verdict == "DROP"` (bloqueo por política MSAC o Gatekeeper). |
| **100320** | 12 | Alta | T1557, T1565 | `error_code == -32001` (fallo de firma MAC SipHash-2-4). |
| **100321** | 12 | Alta | T1565.001 | `error_code == -32003` (ataque de repetición de sesión UUID). |
| **100330** | 12 | Crítica | T1059 | `error_code == -32007` (intento de Prompt Injection / Jailbreak). |
| **100331** | 12 | Crítica | T1048, T1567 | `error_code == -32008` (violación de DLP / Taint sensible en egreso). |
| **100340** | 8 | Media | - | `error_code == -32002` o `-32004` (desborde de presupuesto / timeout). |

---

## 5. Ejemplo de Alerta Procesada en Wazuh Dashboard

### Evento Crudo (JSONL generado por `--audit-log`):
```json
{"timestamp_ms":1774390000123,"component":"mcp_sidecar","session_uuid":8947219084721984,"verdict":"DROP","error_code":-32007,"reason":"Blocked by Capa 8 MSAC Firewall: Prompt injection detected in arguments","active_taints":["PROMPT_INJECTION"],"source_descriptor":"mcp:client:tools/call"}
```

### Documento de Alerta Indexado en Wazuh Indexer:
```json
{
  "_index": "wazuh-alerts-4.x-2026.04.18",
  "_source": {
    "timestamp": "2026-04-18T14:26:40.123+0000",
    "rule": {
      "level": 12,
      "description": "Capa 8 CRÍTICO: Intento de Prompt Injection / Jailbreak interceptado en memoria (Zero-Connect)",
      "id": "100330",
      "mitre": {
        "id": ["T1059"]
      },
      "groups": ["ilp", "prompt_injection", "gatekeeper", "msac"]
    },
    "data": {
      "component": "mcp_sidecar",
      "session_uuid": "8947219084721984",
      "verdict": "DROP",
      "error_code": -32007,
      "reason": "Blocked by Capa 8 MSAC Firewall: Prompt injection detected in arguments",
      "active_taints": ["PROMPT_INJECTION"]
    }
  }
}
```
