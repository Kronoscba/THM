# Reporte PTES — TryHackMe: Infinity Pool

## 1. Executive Summary

- **Alcance autorizado**: `10.66.149.92` (TryHackMe — Hacker Holidays: Infinity Pool)
- **Fecha**: 2026-08-29 · **Tipo**: Laboratorio educativo autorizado
- **Resultado**: Compromiso total — flags de usuario y root obtenidas
- **Nivel de riesgo global**: **Critical**
- **Tiempo invertido**: ~1.5 horas

Hallazgos críticos (lenguaje de negocio):
1. La web pública de "Byte Lotus" filtra un endpoint interno de personal que permite **ejecutar comandos** en el servidor sin autenticación (RCE como usuario `web`).
2. Un servicio interno de monitorización **(Watchtower)** expone credenciales de telefonía en texto plano, sin rotar, en una API accesible en el propio host.
3. Un servicio interno de automatización que corre como **root** permite **ejecutar comandos como root** a través de su endpoint de exportación (2ª inyección de comandos), usando una clave secreta filtrada en un campo visible de la interfaz de usuario.
4. Resultado: **flag de root** `THM{tr4c3d_t0_th3_h0r1z0n}` obtenida.

---

## 2. Methodology

| Fase PTES | Acciones |
|-----------|----------|
| Pre-engagement | Definición de alcance: `.target` (10.66.149.92), callback tun0 (192.168.134.200) |
| Intelligence Gathering | `rustscan`, nmap `-sC -sV`, método de `app.js` + `robots.txt`, mapado de servicios internos loopback |
| Threat Modeling | Vectores: web (HTTP 80), servicios internos (Watchtower 3000, Automation 9000, FreePBX/Asterisk 8080/8088/8089, MySQL 3306, AMI 5038). Descartados SSH (publickey-only), FreePBX admin (sin credenciales válidas), MySQL (sin acceso) |
| Vulnerability Analysis | Inyección de comandos web (CWE-78); exposición de credenciales (CWE-200); 2ª inyección de comandos root |
| Exploitation | 2 RCE por command injection encadenados: `web` → `root` |
| Post Exploitation | Escalada vía clave de automatización filtrada; rebase por túnel chisel |
| Reporting | Este documento |

---

## 3. Findings

### [FIND-01] Information Disclosure vía robots.txt y comentario JS
- **Severidad**: Medium · **CWE-200** · **Ubicación**: `/robots.txt`, `/static/app.js`
- **Descripción**: `robots.txt` revela rutas internas (`/internal/`, `/status`); un comentario TODO en `app.js` revela el endpoint legacy `/internal/netcheck`.
- **Evidencia**: `content/app.js` (comentario: *"the staff connectivity tool at /status posts to the legacy /internal/netcheck handler"*)
- **Impacto**: Abre la puerta al FIND-02.

### [FIND-02] OS Command Injection en `POST /internal/netcheck` (RCE como `web`)
- **Severidad**: Critical · **CVSS 3.1**: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) · **CWE-78**
- **Ubicación**: `10.66.149.92:80 /internal/netcheck` (parámetro `host`)
- **Descripción**: `subprocess.run(f"ping -c 1 {host}", shell=True)` sin sanitizar.
- **Evidencia**:
  - `exploits/netcheck_rce.sh` (helper RCE)
  - Reproducción: `POST /internal/netcheck` con `host=127.0.0.1; id` → `uid=1001(web)`
- **Impacto**: RCE como usuario `web`; permite pivotar a servicios internos y escalar.

### [FIND-03] Plaintext Credential Disclosure en `GET /api/config` (Watchtower 3000)
- **Severidad**: High · **CWE-200 ·** **Ubicación**: `127.0.0.1:3000/api/config`
- **Descripción**: API interna (loopback) devuelve credenciales FreePBX UCP en texto plano, con nota de ops indicando que NO están rotadas.
- **Evidencia**: `loot/creds_plaintext.txt` → `FreePBXUCPTemplateCreator:St4yN0t1c3d_2026`
- **Impacto**: Credenciales de telefonía; pista hacia la clave de automatización.

### [FIND-04] OS Command Injection en `POST /jobs/export` (RCE como `root`)
- **Severidad**: Critical · **CVSS 3.1**: 9.8 · **CWE-78**
- **Ubicación**: `127.0.0.1:9000/jobs/export` (parámetro `report`, autenticado con Bearer)
- **Descripción**: El servicio `cc-automation` (corre como root, ver `cc-automation.service`) construye un comando `tar` con el parámetro `report` sin sanitizar. La clave Bearer `cc_auto_7b3f9a1c4e0d2f6a` estaba filtrada en un campo caller-ID visible en el widget de voicemail del panel UCP.
- **Evidencia**:
  - `POST /jobs/export` + Bearer `cc_auto_7b3f9a1c4e0d2f6a` + `{"report":"x.tgz /var/automation/data; id #"}` → `uid=0(root)`
  - Root flag: `THM{tr4c3d_t0_th3_h0r1z0n}` → `loot/root_flag.txt`
- **Impacto**: **RCE como root** → compromiso total.

---

## 4. Evidence Inventory

| Archivo | Tipo | Hallazgo |
|---------|------|----------|
| `nmap/rustscan_full.txt` | Port scan | Puertos 22/80 |
| `nmap/nmap_detailed.nmap` | Service scan | Gunicorn, OpenSSH |
| `content/app.js` | Código | FIND-01 (hint netcheck) |
| `exploits/netcheck_rce.sh` | Exploit | FIND-02 (RCE web) |
| `loot/creds_plaintext.txt` | Credenciales | FIND-03 / key automation |
| `loot/user_flag.txt` | Flag | `THM{n0_v1s1bl3_3dg3}` |
| `loot/root_flag.txt` | Flag | `THM{tr4c3d_t0_th3_h0r1z0n}` |
| `exploits/chisel` | Tool | Pivote/socks |

---

## 5. Remediation Summary

Prioridad (quick win → largo plazo):
1. **Validar/sanitizar inputs** en `/internal/netcheck` (host) y `/jobs/export` (report) — nunca concatenar a un shell (`shell=False`, subprocess con lista de args).
2. **Rotar credenciales** `FreePBXUCPTemplateCreator` (la propia nota de ops lo demandaba).
3. **No filtrar secretos** (clave automation) en campos visibles tipo caller-ID/display name; usar secret store dedicado.
4. **Least privilege**: `/jobs/export` no debe correr como root; servicio con permisos mínimos.
5. **Autenticar/allowlist** servicios internos (no fiarse solo de loopback una vez hay foothold en el host).

---

## 6. Lessons Learned & Deviations

- **Descartados**: SSH (solo publickey), login admin FreePBX (sin credenciales válidas), AMI Asterisk 5038 (auth falló), MySQL (sin acceso). El vector real NO era forzar FreePBX — era la clave filtrada en el UCP.
- **Desviación**: Se consultó el writeup oficial tras estancamiento en FreePBX — la key venía del panel UCP (widget voicemail, campo caller-ID), no de archivos legibles.
- **Deviación de entorno**: `pwncat-cs` roto en el host (falta `pkg_resources` en Python 3.14) → se usó `ncat` como listener. Discrepancia `.vpn` vs `.vpn_ip` en AGENTS.md.
- **Clave**: encadenar pequeños hallazgos (hint JS → RCE web → Config leak → key caller-ID → RCE root).
