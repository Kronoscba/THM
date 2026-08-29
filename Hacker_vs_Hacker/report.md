# Reporte de Pentest — TryHackMe: *Hacker vs Hacker*

**Autor:** (equipo rojo) · **Fecha:** 2026-06-17
**Alcance:** 1 objetivo autorizado (box THM `Hacker vs Hacker`), modelo de amenaza *authorized adversarial emulation*.
**Objetivo de la prueba:** obtener acceso al servidor de la empresa de reclutamiento (ya comprometido por un atacante previo), evadir su contramedida persistente y capturar las flags de usuario y root.

---

## 1. Metodología

Se utilizó el **Penetration Testing Execution Standard (PTES)** — modelo de 7 fases para pruebas de intrusión autorizadas — adaptado a un único objetivo, complementado con mapeo a **MITRE ATT&CK** para las técnicas ofensivas empleadas. Se eligió PTES porque:

- Es el estándar que mejor encaja con el SOP de `agent.md` (labs autorizados THM/HTB/CTF: verificar alcance antes de ejecutar comandos, separar evidencia por carpeta).
- Las 7 fases cubren de forma ordenada reconocimiento → explotación → post-explotación → reporte, que es exactamente el flujo de la room.
- El mapeo ATT&CK da trazabilidad a cada acción del "segundo hacker" (nosotros) frente a la persistencia del "primer hacker".

> Las fases PTES aplicadas: **(1) Pre-engagement**, **(2) Intelligence Gathering**, **(3) Modeling**, **(4) Vulnerability Analysis**, **(5) Exploitation**, **(6) Post-Exploitation**, **(7) Reporting**.

---

## 2. Pre-engagement / Alcance

- Objetivo: `10.66.171.53` (THM). IP de callback/VPN del atacante: `192.168.134.200` (tun0).
- Superficie autorizada: solo el host objetivo. Sin escaneo de terceros, sin denial-of-service.
- Evidencia organizada en: `nmap/`, `web/`, `loot/`, `exploits/`, `scripts/`, `notes.txt`.

## 3. Intelligence Gathering (Reconocimiento)

**Escaneo de puertos** (rustscan + nmap):

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | OpenSSH  | 8.2p1 Ubuntu |
| 80/tcp | Apache   | 2.4.41 Ubuntu |

Sin sistema operativo explotable vía red; sin servicios adicionales.

**Recon web:** sitio brochure "RecruitSec". Formulario de subida `action="upload.php"` y comentario oculto que señala `/cvs` como riesgo de privacidad.

**Técnica ATT&CK:** `T1595 Active Scanning`, `T1592 Gather Victim Host Information`, `T1593 Search Open Websites/Domains`.

## 4. Modeling (Modelado del entorno)

El servidor aloja una app PHP (Apache + `AddHandler` multi-extensión) y un usuario local `lachlan`. El atacante previo ya tiene presencia (web shell en `/cvs/`, usuario `lachlan`, y un cron de root como contramedida).

## 5. Vulnerability Analysis (Análisis de vulnerabilidades)

- **Filtro de subida roto:** `upload.php` (código filtrado en comentario HTML) solo valida `strpos($target_file, ".pdf")`. Bypass trivial: nombre `shell.pdf.php` → Apache ejecuta PHP por multi-extensión. *Hallazgo:* el archivo estaba defaceado (HTML estático), pero el atacante previo ya había dejado el web shell funcional en `/cvs/shell.pdf.php`.
- **Credenciales en historial:** `.bash_history` de `lachlan` mostraba un cambio de contraseña (`passwd`), revelando `lachlan:thisistheway123`.
- **Hijack de PATH en cron de root:** `/etc/cron.d/persistence` corre como **root** con `PATH=/home/lachlan/bin:/bin:/usr/bin` y llama a `pkill` **sin ruta absoluta**. Como `lachlan` es dueño de `/home/lachlan/bin/`, puede colocar un `pkill` malicioso que el root ejecutará.

## 6. Exploitation (Explotación)

### 6.1 Acceso inicial — web shell (www-data)
- Endpoint del atacante previo reutilizado: `http://10.66.171.53/cvs/shell.pdf.php?cmd=`.
- RCE como `www-data` (sin TTY). Esto confirma el bypass de filtro `.pdf`.

### 6.2 Acceso de usuario — credenciales
- SSH como `lachlan:thisistheway123` → acceso de bajo privilegio.
- `user.txt` → `thm{af7e46b68081d4025c5ce10851430617}`

**Técnica ATT&CK:** `T1505.003 Web Shell`, `T1078 Valid Accounts`, `T1059 Command and Scripting Interpreter`.

## 7. Post-Exploitation (Escalada y evasión de contramedida)

### 7.1 Análisis de la contramedida ("hacker vs hacker")
`/etc/cron.d/persistence` (root, cada ~10 s):

```cron
PATH=/home/lachlan/bin:/bin:/usr/bin
* * * * * root /bin/sleep 1 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
```

La contramedida **mata cualquier shell interactiva** (sesiones en `/dev/pts`) cada 10 s. Pero:
1. Usa `PATH` personalizada con `/home/lachlan/bin` **primero**.
2. Llama a `pkill` sin ruta → resuelve a `/home/lachlan/bin/pkill` (controlable por `lachlan`).

### 7.2 Evasión + escalada (PATH hijack → root)
- Se reemplazó `/home/lachlan/bin/pkill` (755, dueño `lachlan`) por:
  ```sh
  #!/bin/bash
  cp /bin/bash /tmp/rootbash 2>/dev/null
  chmod 4755 /tmp/rootbash 2>/dev/null
  ```
- El cron, al correr como **root**, ejecuta este `pkill` falso → crea `/tmp/rootbash` con **SUID root**.
- Detalle de disparo: el cron solo ejecuta `pkill` cuando `echo nope > /dev/pts/$f` tiene éxito (root puede escribir `/dev/pts/ptmx`), así que basta con que exista una entrada en `/dev/pts` para que el binario SUID se genere.
- Uso: `/tmp/rootbash -p` → `euid=0(root)`.

> Nota de entorno: Apache corre con `PrivateTmp`, por lo que `www-data` no ve `/tmp/rootbash` (namespace aislado). El binario SUID es visible y ejecutable por cualquier usuario real (p. ej. `lachlan`).

### 7.3 Root flag
- `root.txt` → `thm{7b708e5224f666d3562647816ee2a1d4}`

**Técnica ATT&CK:** `T1574.007 Path Interception by PATH Environment Variable`, `T1548.001 Setuid and Setgid`, `T1053.003 Cron`, `T1543.005 (contramedida del atacante)`.

## 8. Hallazgos y remediación

| # | Severidad | Hallazgo | Remediación |
|---|-----------|----------|-------------|
| F1 | Crítica | Filtro de subida basado en `strpos(".pdf")` (bypass `shell.pdf.php`); web shell activo en `/cvs/`. | Validar por **extensión final** y tipo MIME; deshabilitar ejecución PHP en directorios de subidas; eliminar el web shell. |
| F2 | Alta | Contraseña de `lachlan` débil/reutilizable (`thisistheway123`) expuesta en `.bash_history`. | Forzar contraseña robusta, rotarla, limpiar historial; MFA. |
| F3 | Crítica | PATH hijack en cron de root: `/home/lachlan/bin` antes que los bins del sistema y `pkill` sin ruta. | Nunca poner directorios de usuario escribibles antes en `PATH` de root; usar rutas absolutas en crons; `<` permisos de `/home/lachlan/bin` a `root:root 755`. |
| F4 | Media | Contramedida del atacante (cron mata shells) convive con la caja comprometida. | Reimaginar/parchear la caja; no "curar" en caliente un host ya bajo control. |

## 9. Conclusión

Se obtuvo acceso de **root** evadiendo la contramedida del atacante previo mediante un **PATH hijack en un cron de root** (técnica clásica de escalada por manipulación de `PATH` en tareas programadas). La lección central: un cron ejecutado como root no debe incluir en su `PATH` directorios propiedad de usuarios no privilegiados, ni invocar binarios sin ruta absoluta.

---

## Anexo A — Evidencia
- `loot/flags.txt` — flags de usuario y root.
- `loot/creds_plaintext.txt` — `lachlan:thisistheway123`.
- `notes.txt` — cadena de explotación resumida.
- `nmap/` — resultados de escaneo.
- `web/` — requests/recon del web shell.

## Anexo B — Línea de tiempo (ATT&CK)
1. `T1595/T1592` Recon (puertos 22/80).
2. `T1505.003` Web shell en `/cvs/` → `www-data`.
3. `T1078` SSH con credencial filtrada → `lachlan`.
4. `T1053.003/T1574.007` Cron de root + PATH hijack → `pkill` malicioso.
5. `T1548.001` Binario SUID (`/tmp/rootbash`) → **root**.
