# Madness — TryHackMe Room

## Executive Summary

- **Target**: 10.66.152.171
- **Date**: 2026-07-05
- **Type**: CTF / Penetration Testing Assessment
- **Risk Level**: Critical (full compromise achieved: user + root)
- **Total Time**: ~30 min

The assessment successfully compromised the target through a multi-stage attack chain involving steganography, web parameter fuzzing, and a known SUID privilege escalation vector. Both user and root flags were captured.

---

## Methodology (PTES)

### 1. Intelligence Gathering

**Herramienta**: `rustscan` → `nmap -sV`
- Puerto 22/tcp: OpenSSH 7.2p2 Ubuntu
- Puerto 80/tcp: Apache httpd 2.4.18 (Ubuntu)

Archivo: `nmap/initial`

### 2. Threat Modeling

Vectores identificados:
- Web server con imagen JPEG con header corrupto (PNG magic bytes → JPEG real)
- Directorio oculto `/th1s_1s_h1dd3n` con parámetro `secret` (0-99)
- Imagen con datos embebidos via steghide/stegseek
- SUID `/bin/screen-4.5.0` vulnerable

Vectores descartados: SSH brute force (no necesario), otros servicios (solo 22 y 80).

### 3. Vulnerability Analysis

| Herramienta | Objetivo | Resultado |
|-------------|----------|-----------|
| `xxd`, `file` | Analizar header de thm.jpg | Header PNG corrupto, JPEG real tras fix |
| `curl` | Explorar directorio oculto | `?secret=73` revela passphrase |
| `stegseek` | Extraer datos de imágenes | hidden.txt (usuario ROT13) + password.txt |
| `find / -perm -4000` | Enumeración SUID local | `/bin/screen-4.5.0` con SUID root |

### 4. Exploitation

#### Hallazgo 1: Steganografía en imagen del servidor
- **Severidad**: High
- **Ubicación**: http://10.66.152.171/thm.jpg
- **Descripción**: Imagen con header corrupto (PNG en vez de JPEG). Al corregir el header y visualizar, revela directorio `/th1s_1s_h1dd3n`.
- **Evidencia**: `content/proper.jpg`, `content/thm.jpg`
- **Comando de reproducción**:
  ```bash
  # Fix header: cambiar 89 50 4E 47 → FF D8 FF E0
  printf '\xff\xd8\xff\xe0' | dd of=thm.jpg bs=1 seek=0 count=4 conv=notrunc
  ```
- **Impacto**: Divulgación de directorio oculto en el servidor web.

#### Hallazgo 2: Parámetro secret con valores predecibles
- **Severidad**: High
- **Ubicación**: http://10.66.152.171/th1s_1s_h1dd3n/?secret=73
- **Descripción**: El parámetro `secret` acepta valores entre 0-99 (comentario en HTML). `secret=73` retorna passphrase `y2RPJ4QaPF!B`.
- **Evidencia**: `web/`
- **Comando de reproducción**:
  ```bash
  curl -s "http://10.66.152.171/th1s_1s_h1dd3n/?secret=73"
  ```
- **Impacto**: Obtención de passphrase para esteganografía.

#### Hallazgo 3: Datos embebidos en imágenes (steghide/stegseek)
- **Severidad**: Critical
- **Ubicación**: `content/proper.jpg`, `content/5iW7kC8.jpg`
- **Descripción**: Dos imágenes contienen datos ocultos: `proper.jpg` con passphrase `y2RPJ4QaPF!B` extrae usuario `wbxre` (ROT13 → `joker`). La imagen original de la room THM (`5iW7kC8.jpg`) sin passphrase extrae password `*axA&GF8dP`.
- **Evidencia**: `content/hidden.txt`, `content/password.txt`, `content/steg_extracted.txt`
- **Comando de reproducción**:
  ```bash
  stegseek --extract proper.jpg -p "y2RPJ4QaPF!B"
  stegseek --extract 5iW7kC8.jpg -p ""
  echo "wbxre" | tr 'a-z' 'n-za-m'  # → joker
  ```
- **Impacto**: Compromiso total de credenciales SSH.

#### Hallazgo 4: screen-4.5.0 SUID Local Privilege Escalation
- **Severidad**: Critical
- **CVE**: CVE-2017-10683
- **CWE**: CWE-264 (Permissions, Privileges, and Access Controls)
- **CVSS 3.1**: 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Ubicación**: `/bin/screen-4.5.0` (SUID root)
- **Descripción**: GNU Screen 4.5.0 permite a atacantes locales obtener privilegios de root mediante la manipulación de `/etc/ld.so.preload` vía el mecanismo de logging de screen.
- **Evidencia**: `exploits/screen_privesc.sh`
- **Comando de reproducción**:
  ```bash
  # Transferir exploit y ejecutar
  bash /tmp/screen_privesc.sh
  /tmp/rootshell -c 'cat /root/root.txt'
  ```
- **Impacto**: Escalada a root, acceso completo al sistema.

### 5. Post Exploitation

**Usuario**: `joker` vía SSH
**Flags capturadas**:
- `user.txt`: `THM{d5781e53b130efe2f94f9b0354a5e4ea}`
- `root.txt`: `THM{5ecd98aa66a6abb670184d7547c8124a}`

---

## Evidence Inventory

| Archivo | Tipo | Hallazgo |
|---------|------|----------|
| `nmap/initial` | Port scan | Puertos 22, 80 |
| `content/thm.jpg` | Imagen corrupta | Header PNG→JPEG |
| `content/proper.jpg` | Imagen fixeada | Stego con passphrase |
| `content/5iW7kC8.jpg` | Imagen THM room | Stego sin passphrase |
| `content/hidden.txt` | Datos extraídos | Usuario wbxre |
| `content/password.txt` | Datos extraídos | Password *axA&GF8dP |
| `exploits/screen_privesc.sh` | Exploit | LPE screen 4.5.0 |
| `loot/user_flag.txt` | Flag | user.txt |
| `loot/root_flag.txt` | Flag | root.txt |
| `loot/creds.txt` | Credenciales | joker:*axA&GF8dP |

---

## Remediation Summary

| Prioridad | Hallazgo | Esfuerzo | Remedio |
|-----------|----------|----------|---------|
| Critical | screen-4.5.0 SUID | Quick win | Eliminar SUID bit: `chmod -s /bin/screen-4.5.0` o actualizar a ≥4.5.1 |
| Critical | Credenciales en imagen | Short term | No embedder secrets en imágenes públicas |
| High | Parámetro secret brute-forceable | Quick win | Rate limiting, CAPTCHA, eliminar comentario con rango |
| High | Imagen con header corrupto intencional | Informational | No es vulnerabilidad per se |

---

## Lessons Learned

- **Steganografía dual**: Dos imágenes distintas contenían partes complementarias de las credenciales (usuario en una, password en otra).
- **ROT13 como ofuscación mínima**: El usuario `wbxre` es trivialmente decodificable.
- **screen-4.5.0 SUID**: Vector de escalada clásico pero efectivo. La versión 4.5.0 permite escribir a `/etc/ld.so.preload` via el log de screen.
- **Herramienta stegseek**: Reemplaza a steghide para extracción con diccionario o passphrase conocida.
