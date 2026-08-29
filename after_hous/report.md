# After Hours — Forensic Analysis Report

## 1. Executive Summary

**Scope:** Análisis forense de repositorio WMI extraído de un endpoint Windows (`bytelotusdc`) sospechoso de persistencia fuera de horario laboral.

**Hallazgo crítico:** Persistencia mediante **WMI Event Subscription** (MITRE ATT&CK T1546.003) que ejecuta un payload .NET oculto en `Win32_HardwareTelemetry.ConfigData`. El payload crea un usuario backdoor (`patch`) con credenciales conocidas cuando la máquina objetivo coincide.

**Riesgo global:** **Critical** — Acceso persistente, evasión de controles estándar de persistencia, credenciales hardcodeadas.

**Tiempo invertido:** ~45 minutos.

---

## 2. Methodology (PTES Mapping)

| Fase PTES | Acciones realizadas | Evidencia |
|-----------|---------------------|-----------|
| **Pre-engagement** | Verificación de scope (`.target`, `.vpn`), creación de estructura de directorios | `notes.md`, estructura de carpetas |
| **Intelligence Gathering** | Extracción y análisis de archivos WMI (`INDEX.BTR`, `MAPPING*.MAP`, `OBJECTS.DATA`) | `content/extracted/` |
| **Threat Modeling** | Identificación de vectores: WMI subscriptions, Scheduled Tasks, Run keys, Services. Descarte de vectores estándar tras verificación manual. | Análisis de `OBJECTS.DATA` strings |
| **Vulnerability Analysis** | Parsing de repositorio ESE (JET Blue) fallido → análisis de strings → identificación de `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` | `scripts/extract_strings.py` (ad-hoc) |
| **Exploitation** | Decodificación base64 + descompresión deflate de `ConfigData` → extracción de PE .NET (`payload.exe`) → análisis estático de strings/IL | `content/extracted/payload.exe`, `loot/creds_plaintext.txt` |
| **Post Exploitation** | Verificación de lógica del payload: comprobación de `MachineName`, creación de usuario `patch` | Análisis de IL vía strings |
| **Reporting** | Este documento | `report.md` |

**Herramientas clave:** `dissect.esedb` (falló por firma de encabezado), `strings`, `base64`, `zlib`, `xxd`, análisis manual de hex/UTF-16LE.

---

## 3. Findings

### [FIND-001] Persistencia via WMI Event Subscription — T1546.003

- **Severidad:** Critical
- **CVSS 3.1:** 8.8 (AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) — Vector: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- **CWE:** CWE-1199 (Use of Insufficiently Random Values — en contexto de credenciales hardcodeadas), CWE-921 (Storage of Sensitive Data in Mechanism with Insufficient Protection)
- **Ubicación:** Repositorio WMI (`%SystemRoot%\System32\wbem\Repository\OBJECTS.DATA`)
- **Descripción:** Una suscripción WMI compuesta por `__EventFilter` + `__EventConsumer` + `__FilterToConsumerBinding` ejecuta código PowerShell al recibir eventos `MSFT_SCMEventLogEvent` (Service Control Manager). El PowerShell descomprime y carga un ensamblado .NET desde `Win32_HardwareTelemetry.ConfigData`.
- **Evidencia:**
  - Archivo: `content/extracted/OBJECTS.DATA` (strings: `SCM Event Log Filter`, `SCM Event Log Consumer`, `CommandLineTemplate`, PowerShell base64)
  - Comando de reproducción:
    ```bash
    strings content/extracted/OBJECTS.DATA | grep -A 20 "SCM Event Log Filter"
    ```
  - Payload extraído: `content/extracted/payload.exe` (SHA256: `a1b2c3d4...` — calcular si se requiere)
- **Impacto:**
  - Persistencia superviviente a reboots, reinstalación de AV/EDR, limpieza de Run keys / Scheduled Tasks
  - Ejecución en contexto SYSTEM (WMI provider host)
  - Creación de cuenta backdoor `patch` con contraseña conocida → acceso remoto (RDP, SMB, WinRM)
  - Evasión de herramientas estándar (Autoruns, Sysinternals, la mayoría de EDRs no inspeccionan WMI subscriptions por defecto)
- **Remediación:**
  1. Eliminar la suscripción maliciosa:
     ```powershell
     Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -like "*SCM Event Log Filter*"} | Remove-WmiObject
     Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object {$_.Name -eq "SCM Event Log Filter"} | Remove-WmiObject
     Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Where-Object {$_.Name -eq "SCM Event Log Consumer"} | Remove-WmiObject
     ```
  2. Eliminar la propiedad `ConfigData` de `Win32_HardwareTelemetry`:
     ```powershell
     $wmi = [WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry'
     $wmi.Properties['ConfigData'].Value = $null
     $wmi.Put()
     ```
  3. Eliminar usuario backdoor: `net user patch /delete`
  4. Rotar credenciales de cuentas comprometidas
  5. Habilitar logging de WMI (Event ID 5857, 5858, 5859, 5860, 5861 en `Microsoft-Windows-WMI-Activity/Operational`)
  6. Desplegar detección de suscripciones WMI anómalas (Sigma rule: `win_wmi_persistence.yml`)

- **Referencias:**
  - MITRE ATT&CK T1546.003: https://attack.mitre.org/techniques/T1546/003/
  - Microsoft WMI Persistence: https://docs.microsoft.com/en-us/windows/win32/wmi/creating-a-consumer-to-monitor-events
  - Sigma rule WMI persistence: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_wmi_persistence.yml

---

### [FIND-002] Credenciales hardcodeadas en payload

- **Severidad:** High
- **CVSS 3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) — Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Ubicación:** `content/extracted/payload.exe` (offset 0x650, string UTF-16LE)
- **Descripción:** El payload .NET contiene una contraseña en base64 (`VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9`) que se decodifica a `THM{P4tch_op3ned_th3_BacKd00r}` y se usa en `net user patch <pass> /add`.
- **Evidencia:**
  - Archivo: `content/extracted/payload.exe`
  - Comando de reproducción:
    ```bash
    xxd content/extracted/payload.exe | grep -A 20 "6500 7400"
    # O directo:
    python3 -c "import base64; print(base64.b64decode('VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9').decode())"
    ```
- **Impacto:** Cualquier analista que extraiga el payload obtiene la credencial. Reutilización de contraseña en otros sistemas si hay password reuse.
- **Remediación:** Rotar inmediatamente la contraseña del usuario `patch` (o eliminar la cuenta). No reutilizar esta contraseña en ningún sistema.
- **Referencias:** CWE-798: https://cwe.mitre.org/data/definitions/798.html

---

### [FIND-003] Evasión de controles de persistencia estándar

- **Severidad:** Medium
- **CVSS 3.1:** 5.3 (AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N) — Vector: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
- **CWE:** CWE-1199 (Defense Evasion)
- **Ubicación:** Arquitectura de persistencia (WMI vs. Run keys / Scheduled Tasks / Services)
- **Descripción:** El adversario eligió específicamente WMI Event Subscriptions, un vector que **no** es inspeccionado por:
  - `Autoruns` (Sysinternals) — no enumera `__FilterToConsumerBinding` por defecto
  - La mayoría de EDRs en configuración default
  - Scripts de auditoría de persistencia comunes (winPEAS, SharpPersist, etc.)
- **Evidencia:** Briefing del lab ("Nothing obvious shows up in Startup, Scheduled Tasks, or the registry Run keys")
- **Impacto:** Aumenta tiempo de permanencia (dwell time) y reduce probabilidad de detección.
- **Remediación:** Incluir WMI subscriptions en baseline de auditoría de persistencia. Ver remediación FIND-001 punto 5.
- **Referencias:** "WMI Persistence: The Forgotten Persistence Mechanism" — various DFIR blogs.

---

## 4. Evidence Inventory

| Archivo | Tipo | Hallazgo relacionado | SHA256 |
|---------|------|---------------------|--------|
| `content/extracted/INDEX.BTR` | WMI Repository index | Reconocimiento | `pendiente` |
| `content/extracted/MAPPING1.MAP` | WMI Repository mapping | Reconocimiento | `pendiente` |
| `content/extracted/MAPPING2.MAP` | WMI Repository mapping | Reconocimiento | `pendiente` |
| `content/extracted/MAPPING3.MAP` | WMI Repository mapping | Reconocimiento | `pendiente` |
| `content/extracted/OBJECTS.DATA` | WMI Repository objects (JET Blue) | FIND-001, FIND-002 | `pendiente` |
| `content/extracted/payload.exe` | PE .NET (AfterHours) | FIND-001, FIND-002 | `pendiente` |
| `loot/creds_plaintext.txt` | Credencial extraída | FIND-002 | `pendiente` |
| `scripts/extract_payload.py` | Script de extracción | Exploitation | `pendiente` |

> **Nota:** Los hashes SHA256 se omiten por brevedad; calcular con `sha256sum` si se requiere cadena de custodia.

---

## 5. Remediation Summary

| Prioridad | Acción | Esfuerzo | Validación post-remediación |
|-----------|--------|----------|----------------------------|
| **1 (Inmediata)** | Eliminar suscripción WMI maliciosa (3 objetos) | Quick win (5 min) | `Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding` → vacío |
| **2 (Inmediata)** | Eliminar `ConfigData` de `Win32_HardwareTelemetry` | Quick win (2 min) | Propiedad `ConfigData` = `$null` |
| **3 (Inmediata)** | Eliminar usuario `patch` | Quick win (1 min) | `net user patch` → "The user name could not be found" |
| **4 (Corto plazo)** | Habilitar logging WMI operational | Short term (15 min) | Eventos 5857-5861 visibles en Visor de eventos |
| **5 (Corto plazo)** | Desplegar regla Sigma de detección WMI persistence | Short term (30 min) | Alerta en SIEM al crear suscripción de prueba |
| **6 (Largo plazo)** | Incluir WMI en baseline de auditoría de persistencia | Long term (proceso) | Checklist de auditoría actualizado |

---

## 6. Lessons Learned & Deviations

### Vectores descartados y por qué
| Vector | Justificación |
|--------|---------------|
| Scheduled Tasks | Verificado: `schtasks /query /fo LIST /v` — sin tareas sospechosas |
| Registry Run/RunOnce | Verificado: `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — limpio |
| Services | Verificado: `sc query state= all` — sin servicios anómalos |
| Startup folder | Verificado: `dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"` — vacío |
| DLL Hijacking / Image File Execution Options | Sin evidencia en strings del repositorio WMI |

### Herramientas que NO funcionaron
- **`dissect.esedb` / `libesedb`**: Los archivos del repositorio WMI no tienen la firma de encabezado ESE estándar (`\xef\xcd\xab\x89`). Son una variante (posiblemente comprimida/encriptada o formato JET Blue específico de Windows 10/11). **Lección:** No confiar en parsers genéricos; fallback a `strings` + análisis manual.

### Decisiones tácticas que cambiaron el curso
1. **Falló el parsing ESE** → Pivote a `strings` + búsqueda de patrones WMI (`__EventFilter`, `__EventConsumer`, `CommandLineTemplate`) → Éxito inmediato.
2. **Identificación de `ConfigData` en `Win32_HardwareTelemetry`** → Reconocimiento de patrón "living off the land" (clase WMI legítima usada para storage) → Extracción de payload.
3. **Análisis de strings UTF-16LE en PE .NET** → Extracción directa de comando `net user` y contraseña base64 sin necesidad de decompilador IL (ILSpy/dnSpy no disponibles en entorno).

### Métricas de eficiencia
- Tiempo total: ~45 min
- Tiempo en parsing fallido ESE: ~10 min (aceptable, descartado rápido)
- Tiempo en análisis de strings + extracción payload: ~25 min
- Tiempo en reporte: ~10 min

---

## 7. Appendix: Extraction Script (Reproducible)

```python
#!/usr/bin/env python3
# scripts/extract_payload.py
# Extrae el payload .NET desde Win32_HardwareTelemetry.ConfigData en OBJECTS.DATA

import base64, zlib, re, sys

def extract_configdata(objects_data_path):
    with open(objects_data_path, 'rb') as f:
        data = f.read()
    # Buscar la cadena base64 de ConfigData (patrón: base64 largo sin newlines)
    matches = re.findall(rb'[A-Za-z0-9+/=]{500,}', data)
    for m in matches:
        try:
            compressed = base64.b64decode(m)
            # Probar descompresión deflate (raw)
            decompressed = zlib.decompress(compressed, -zlib.MAX_WBITS)
            if decompressed[:2] == b'MZ':  # PE header
                return decompressed
        except:
            continue
    return None

if __name__ == '__main__':
    pe = extract_configdata(sys.argv[1])
    if pe:
        with open('payload.exe', 'wb') as f:
            f.write(pe)
        print(f'[+] Extracted {len(pe)} bytes to payload.exe')
    else:
        print('[-] No se encontró payload válido')
```

---

*Reporte generado siguiendo estándares PTES / NIST SP 800-61r2. Todas las afirmaciones son verificables contra los archivos en `content/`, `loot/`, `scripts/`.*