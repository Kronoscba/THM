# Reporte de Evaluación — TryHackMe "The Hollow Shell"

## 1. Executive Summary

- **Alcance autorizado**: TryHackMe (laboratorio de entrenamiento), target `10.65.146.116`, fecha 2026-08-29, tipo CTF/assessment educativo.
- **Resultado**: Se obtuvo **acceso inicial (RCE)** sobre el servicio web en el puerto 5000 mediante **ZIP Slip** en la funcionalidad de subida de componentes (`/upload`), logrando reverse shell interactiva.
- **Hallazgo crítico**: Un usuario autenticado puede subir un archivo ZIP malicioso cuyo manifiesto `shell.json` permite travesía de directorios (`../`) que escribe un script Python en la carpeta `hooks/` de la aplicación. El framework ejecuta los hooks post-instalación, otorgando ejecución remota de código.
- **Riesgo global**: **High** (requiere autenticación previa, pero las credenciales se obtienen trivialmente al enumerar el código fuente de `/login`).
- **Tiempo total invertido**: ~70 minutos (02:26–03:40).

---

## 2. Methodology (PTES)

| Fase PTES | Acción | Evidencia |
|---|---|---|
| Pre-engagement | Definición de alcance: `.target`, `.vpn` | `.target`, `.vpn` |
| Intelligence Gathering | Escaneo de puertos (rustscan) + probe web (httpx/manual) | `nmap/rustscan_initial.xml` |
| Threat Modeling | Puertos 22 y 5000; descartado SSH (sin credenciales aún), enfocado en web | — |
| Vulnerability Analysis | Fuzzing de rutas + análisis del flujo de autenticación y subida | `web/ffuf_results.json`, `web/ffuf_results_auth.json` |
| Exploitation | Subida de ZIP malicioso con ZIP Slip → reverse shell | `exploits/exploit.py`, `exploits/evil.zip`, `scripts/probe1.py`, `scripts/probe2.py` |
| Post Exploitation | Acceso a shell interactiva, captura de flag | `loot/user_flag.txt` |
| Reporting | Este documento | — |

### Trabajo técnico desglosado

**Intelligence Gathering**
- `rustscan` → puertos abiertos: `22/tcp` (OpenSSH 9.6p1 Ubuntu), `5000/tcp` (Gunicorn).
- `ffuf` no autenticado → solo `/login` (200). Con cookie de sesión → `/dashboard` (200) y `/login` (200).

**Authentication**
- Comentario HTML en `/login` filtra credenciales: `concierge:StayNoticed2024!` → `loot/creds_plaintext.txt`.
- Login OK → cookie de sesión firmada por Flask (`session=eyJzdGFmZiI6...`), persistida en `cookies.txt`.

**Vulnerability Analysis (Gate)**
- Con sesión, `ffuf` revela `/upload` (subida de "shell" en ZIP).
- Al analizar el flujo: se sube un `.zip` que debe contener `shell.json` (manifiesto con `name` y `assets`).
- Hipótesis priorizada: el framework procesa el manifiesto y ejecuta scripts en `hooks/` durante la instalación.
- Se descartaron vectores sin evidencia (SQLi, SSTI, LFI) por ausencia de superficie previa — conforme al anti-patrón "spray and pray".

**Exploitation**
- `scripts/probe1.py`: validó upload legítimo y dump de respuestas → confirmó estructura esperada.
- `scripts/probe2.py`: probó ZIP Slip a `../static/pwn.txt` (profundidades 1–11) y keys de hook por OOB — validación de ruta de escritura.
- `exploits/exploit.py`: vector final — ZIP con `../..` + `hooks/evil.py` conteniendo reverse shell Python hacia `192.168.134.200:4444`.
- Resultado: conexión entrante al listener, shell interactiva `(/bin/bash)`.

---

## 3. Findings

### [FIND-001] ZIP Slip en la subida de componentes (`/upload`) — Ejecución Remota de Código

- **Severidad**: High
- **CVSS 3.1 Score**: 9.1 — vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Ubicación**: `http://10.65.146.116:5000/upload` (autenticado)
- **Descripción**: La subida no valida los nombres de archivo internos del ZIP. Un nombre `../../hooks/evil.py` escapa del directorio de extracción y escribe en `hooks/`, carpeta cuyos scripts el framework ejecuta al instalar el componente (gancho post-instalación). Resultado: RCE como el usuario del servicio.
- **Evidencia**:
  - Archivo: `exploits/exploit.py` (genera `evil.zip` con entrada `../../hooks/evil.py`).
  - Archivo: `nmap/rustscan_initial.xml` (puerto 5000, Gunicorn).
  - Archivo: `loot/creds_plaintext.txt` (credenciales usadas para autenticación).
  - Flag: `loot/user_flag.txt` → `THM{z1p_sl1pp3d_1nt0_a_sh3ll}`
  - Reproducción:
    1. `python3 exploits/exploit.py` (crea `exploits/evil.zip`).
    2. `curl -b cookies.txt -F "shell=@exploits/evil.zip" http://10.65.146.116:5000/upload`
    3. Listener en `4444` recibe la reverse shell.
- **Impacto**: Ejecución remota de código, acceso inicial a la máquina, pivoteo posible, compromiso total del servicio web.
- **Remediación**:
  1. Sanear/validar cada nombre dentro del ZIP contra `../`, rutas absolutas y device paths (normalizar con `os.path.realpath`/`zipfile` + validación de prefijo).
  2. Extraer siempre dentro de un directorio temporal dedicado por usuario, jamás en rutas de ejecución de código.
  3. No ejecutar hooks bajo el directorio web; tratar los componentes como datos inertes y evaluarlos en sandbox.
  4. Bloquear símbolos peligrosos (`..`, `\`, `/` inicial) en el manifiesto `shell.json`.
- **Referencias**: CWE-22; TryHackMe room "The Hollow Shell".

---

## 4. Evidence Inventory

| Archivo | Tipo | Hallazgo relacionado | Hash SHA256 |
|---|---|---|---|
| `nmap/rustscan_initial.xml` | Port scan | Reconocimiento inicial | — |
| `web/ffuf_results.json` | Content discovery | `/login` | — |
| `web/ffuf_results_auth.json` | Content discovery | `/dashboard` | — |
| `loot/creds_plaintext.txt` | Credenciales | Auth | — |
| `cookies.txt` | Sesión | Auth | — |
| `scripts/probe1.py` | PoC | Validación de upload | — |
| `scripts/probe2.py` | PoC | ZIP Slip + hook OOB | — |
| `exploits/exploit.py` | Exploit | ZIP Slip → RCE | — |
| `exploits/evil.zip`, `exploits/shell.zip` | Payload | RCE | — |
| `loot/user_flag.txt` | Prueba | `THM{z1p_sl1pp3d_1nt0_a_sh3ll}` | — |

---

## 5. Remediation Summary

1. **Quick win**: Validación de rutas del ZIP (ZIP Slip) — esfuerzo bajo, elimina el vector principal.
2. **Short term**: Sandbox de ejecución de hooks; aislar extracción por usuario.
3. **Long term**: Rediseñar el proceso de componentes (firma/verificación de manifiesto, build pipeline sin acceso web).

---

## 6. Lessons Learned & Deviations

- **Vectores descartados**: SSH (sin credenciales en esa fase), SQLi/SSTI/LFI (sin evidencia de superficie — decisión conforme al Decision Framework §9 del `agent.md`).
- **Herramientas que requirieron iteración**: el `upload_shell.py` inicial no generaba manifiesto válido completo; se corrigió con `probe1.py` (dump de respuestas) antes de construir el exploit final.
- **Decisión táctica clave**: confirmar la estructura del manifiesto y la ruta de extracción (probe1/probe2) antes del disparo final evitó ruido y falsos positivos.
- **N/A para escalada de privilegios**: la room concluye con el acceso inicial y la flag de usuario.