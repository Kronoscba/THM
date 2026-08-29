# Flatline — Reporte de Explotación

## Metodología aplicada
- **Metodología de proceso: PTES** (Penetration Testing Execution Standard). Es la correcta para este ejercicio porque es un *pentest de infraestructura/red* con fases lineales: reconocimiento → enumeración → análisis de vulnerabilidades → explotación → post-explotación → reporte.
- **Framework de TTPs: MITRE ATT&CK (Enterprise)**. Se usa como capa complementaria para mapear las tácticas/técnicas empleadas (no sustituye a PTES, lo enriquece).
- **OWASP: NO APLICA**. OWASP WSTG / API Security Top 10 cubre *aplicaciones web*. Este lab no tiene app web en scope (solo RDP y `mod_event_socket` de FreeSWITCH), por lo que OWASP no es el marco adecuado.

---

## 1. Executive Summary
- **Alcance**: Máquina `Flatline` (TryHackMe), objetivo `10.65.178.236`, entorno autorizado (lab educativo).
- **Hallazgo crítico**: Exposición del `mod_event_socket` de FreeSWITCH (TCP 8021) con la contraseña por defecto `ClueCon` → RCE como `Nekrotic` (miembro de `Administrators`).
- **Nivel de riesgo global**: Critical.
- **Flags**:
  - user: `THM{64bca0843d535fa73eecdc59d27cbe26}`
  - root: `THM{8c8bc5558f0f3f8060d00ca231a9fb5e}`

## 2. Methodology (PTES)
- **Pre-engagement**: definición de alcance vía `.target` (10.65.178.236) y `.vpn` (callback 192.168.134.200).
- **Intelligence Gathering**: `rustscan` + `nmap -sC -sV` → `3389/tcp` (RDP, Win Server 2019) y `8021/tcp` (FreeSWITCH mod_event_socket). Ver `nmap/detailed.nmap`.
- **Threat Modeling**: vector priorizado = servicio de gestión expuesto en 8021 con credenciales débiles por defecto (frente a RDP que no tenía credenciales conocidas).
- **Vulnerability Analysis**: FreeSWITCH v1.10.1 con `mod_event_socket` autenticándose con `ClueCon` (default). El plano `api` permite `system` → ejecución de comandos OS.
- **Exploitation**: autenticación al socket + `api system <cmd>` como `WIN-EOM4PK0578N\Nekrotic`. Script `scripts/fs_socket.py`.
- **Post-Exploitation / Privesc**: `Nekrotic` ∈ `Administrators`, pero `root.txt` tenía DACL que denegaba acceso. El token del servicio FreeSWITCH porta privilegios admin completos → `takeown` + `icacls /grant` recuperan el acceso.
- **Reporting**: este documento.

## 3. MITRE ATT&CK Mapping (Enterprise)
| Táctica | Técnica | Aplicación en el lab |
|---------|---------|----------------------|
| Reconnaissance / Discovery | T1046 Network Service Discovery | Escaneo de puertos (nmap) |
| Discovery | T1033 System Owner/User Discovery | `whoami`, `net user` |
| Discovery | T1083 File and Directory Discovery | `dir` del Desktop |
| Initial Access | T1078 Valid Accounts | Auth al event socket con credencial por defecto `ClueCon` |
| Execution | T1059.003 Command and Scripting Interpreter: Windows Command Shell | `api system` ejecuta `cmd.exe` |
| Execution | T1059.001 Command and Scripting Interpreter: PowerShell | `Get-Content`, `icacls` vía PowerShell |
| Privilege Escalation | T1222.001 File and Directory Permissions Modification | `takeown` + `icacls /grant` para leer `root.txt` |

## 4. Findings

### [FIND-001] FreeSWITCH mod_event_socket expuesto con credencial por defecto (Critical)
- **CWE**: CWE-798 (Use of Hard-coded / Default Credentials)
- **Ubicación**: `10.65.178.236:8021`
- **Descripción**: FreeSWITCH expone `mod_event_socket` en 8021 autenticándose con la contraseña por defecto `ClueCon`, permitiendo a cualquiera ejecutar comandos del plano `api` (incl. `api system`) en el contexto de la cuenta del servicio.
- **Reproducción**:
  ```
  python3 scripts/fs_socket.py 10.65.178.236 8021 "api status" ClueCon
  python3 scripts/fs_socket.py 10.65.178.236 8021 "api system whoami" ClueCon
  ```
- **Impacto**: RCE como `Nekrotic` (local admin).
- **Remediación**: cambiar la contraseña en `event_socket.conf` (`<param name="password" .../>`), o bindear el socket a `127.0.0.1` / restringir con firewall.

### [FIND-002] root.txt con DACL restrictiva — privesc por recuperación de ownership (Medium)
- **Ubicación**: `C:\Users\Nekrotic\Desktop\root.txt`
- **Descripción**: la flag de root no era legible por `Nekrotic` pese a ser administrador (DACL denegaba acceso). Como el token del servicio conserva privilegios admin completos, `takeown` + `icacls /grant` recuperaron el acceso.
- **Reproducción**:
  ```
  api system cmd /c "takeown /f C:\Users\Nekrotic\Desktop\root.txt && icacls C:\Users\Nekrotic\Desktop\root.txt /grant Nekrotic:F"
  api system type C:\Users\Nekrotic\Desktop\root.txt
  ```
- **Remediación**: no ubicar flags en rutas accesibles a cuentas de servicio; aplicar mínimo privilegio a las cuentas de servicio.

## 5. Evidence Inventory
| Archivo | Tipo | Hallazgo |
|---------|------|----------|
| `nmap/detailed.nmap` | Port/service scan | FIND-001 |
| `scripts/fs_socket.py` | PoC/exploit | FIND-001 |
| `loot/user_flag.txt` | Flag user | — |
| `loot/root_flag.txt` | Flag root | FIND-002 |

## 6. Lessons Learned
- El token de un servicio Windows que corre como miembro de `Administrators` conserva privilegios completos (sin split-token UAC) → útil para `takeown`/`icacls`.
- No asumir que "admin" implica leer cualquier archivo: verificar siempre la DACL explícita.
- Para labs de infraestructura, PTES es la metodología de proceso; MITRE ATT&CK mapea las TTPs; OWASP queda fuera de scope al no haber app web.
