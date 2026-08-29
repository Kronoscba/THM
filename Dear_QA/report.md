# REPORT — TryHackMe "DearQA" (Pwn / Reverse Engineering)

**Classification:** Authorized training lab (CTF) — TryHackMe room "DearQA".
**Scope:** Target `10.65.178.5`, TCP port `5700` (network service binary `DearQA`).
**Assessment type:** Binary exploitation / stack buffer overflow → remote code execution.
**Standard:** PTES (Penetration Testing Execution Standard) + CWE/CVSS classification.
**Date:** 2025-08-27.

---

## 1. Executive Summary

Se comprometió el servicio en el puerto 5700 mediante un **desbordamiento de pila (stack buffer overflow)** clásico 
en el binario `DearQA`. El binario carece de mitigaciones básicas (sin PIE, sin stack canary, stack ejecutable), 
permitiendo sobrescribir la dirección de retorno de `main` para redirigir la ejecución a una función embebida 
("secret function" / `vuln`) que ejecuta `/bin/bash`, otorgando una shell remota como el usuario `ctf` (uid 1000).

- **Hallazgo crítico:** RCE remota sin autenticación vía stack buffer overflow.
- **Nivel de riesgo global:** **Critical (9.8 CVSS 3.1)**.
- **Resultado:** Lectura de flag de usuario `THM{PWN_1S_V3RY_E4SY}` en `/home/ctf/flag.txt`.
- **Tiempo invertido:** ~20 min (análisis estático + exploit + shell).

---

## 2. Methodology (PTES mapeado a acciones)

| Fase PTES | Acción real | Evidencia |
|-----------|-------------|-----------|
| Pre-engagement | Definir alcance (`.target`=10.65.178.5, `.vpn`) y verificar autorización del lab | `.target`, `.vpn` |
| Intelligence Gathering | Conexión de prueba al puerto 5700 + análisis del binario provisto en `content/` | banner del servicio, `file` del binario |
| Threat Modeling | Vectores: binario de red con input de usuario no acotado → BOF. Descartado web/AD (no aplica) | disassembly de `main`/`vuln` |
| Vulnerability Analysis | `objdump`/`readelf`: no PIE, no canary, GNU_STACK RWE, función `vuln` con `execve("/bin/bash")` | `nmap/` no requerido; `exploits/` contiene el análisis |
| Exploitation | Payload `b"A"*40 + p64(0x400686)` enviado por socket → shell | `exploits/dearqa_exploit.py`, salida de shell |
| Post Exploitation | Enumeración local, lectura de flag | `exploits/grab_flag.py`, `loot/user_flag.txt` |
| Reporting | Este documento | `report.md` |

### Decision framework (evidencia → acción)
- El banner "I am sysadmin, i am new in developing" + `scanf("%s")` sugieren input sin validación → justifica análisis de desbordamiento antes que fuzzing de red.
- `readelf` confirma mitigaciones ausentes → el salto a la función "win" (`vuln`) es el camino mínimo, no se requiere ret2libc ni shellcode.

---

## 3. Findings

### [FIND-001] Stack-based Buffer Overflow → Remote Code Execution
- **Severidad:** Critical
- **CVSS 3.1 Score:** 9.8 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWE:** CWE-121 (Stack-based Buffer Overflow) / CWE-120 (Classic Buffer Overflow)
- **CVE:** N/A (binario de laboratorio, no un producto con CVE asignado)
- **Ubicación:** `10.65.178.5:5700` — binario `DearQA`, función `main` (lectura con `scanf`)
- **Descripción:** `main` declara un buffer de 32 bytes en `[rbp-0x20]` y lo llena con `scanf("%s", buf)` sin límite 
	de longitud. Al no existir stack canary, el atacante sobrescribe el saved RBP (8 B) y la dirección de retorno. 
	El binario expone además una función `vuln()` (`0x400686`) que imprime un mensaje y ejecuta 
`execve("/bin/bash", NULL, NULL)`. Redirigiendo el retorno a `0x400686` se obtiene una shell.
- **Evidencia:**
  - Binario: `content/DearQA-1627223337406.DearQA`
  - Desensamblado de `main` (buffer `rbp-0x20`, `scanf` ilimitado):
    ```
    4006fd: lea rax,[rbp-0x20]
    400704: mov edi,0x400851        # "%s"
    40070e: call __isoc99_scanf
    ```
  - Desensamblado de `vuln` (win function):
    ```
    4006b7: mov edi,0x4007f9        # "/bin/bash"
    4006bc: call execve
    ```
  - Exploit: `exploits/dearqa_exploit.py`
  - Salida de shell:
    ```
    ctf@ip-10-65-178-5:/home/ctf$ id
    uid=1000(ctf) gid=1000(ctf) groups=1000(ctf),...
    ```
- **Impacto:** RCE completa como `ctf` (lectura/escritura en el sistema, pivote potencial). Sin autenticación ni 
	interacción del usuario.
- **Remediación:**
  1. Reemplazar `scanf("%s", buf)` por lectura acotada (`fgets`/`scanf("%31s")`) o usar `read()` con límite estricto.
  2. Compilar con mitigaciones: `-fstack-protector-all`, `-pie -fPIE`, `-D_FORTIFY_SOURCE=2`, y NX (`-z noexecstack`).
  3. Evitar funciones "win" que ejecuten shells; validar todo input en el límite de confianza.
- **Referencias:**
  - CWE-121: https://cwe.mitre.org/data/definitions/121.html
  - CWE-120: https://cwe.mitre.org/data/definitions/120.html

### [FIND-002] Ausencia de mitigaciones de compilación (defense-in-depth)
- **Severidad:** High (facilitador de FIND-001)
- **CWE:** CWE-1128 (stack canary ausente) / CWE-119
- **Ubicación:** binario `DearQA`
- **Descripción:** El ELF no es PIE (`Type: EXEC`, base 0x400000 fija), no tiene stack canary 
	(prologue sin `%fs:0x28`), y `GNU_STACK` es `RWE` (ejecutable). Esto convirtió un BOF en RCE trivial.
- **Evidencia:** `readelf -l` → `GNU_STACK ... RWE`; direcciones fijas en `0x400xxx`.
- **Remediación:** Recompilar con CADA mitigación listada en FIND-001.

---

## 4. Evidence Inventory

| Archivo | Tipo | Hallazgo | SHA256 |
|---------|------|----------|--------|
| `content/DearQA-1627223337406.DearQA` | Binario objetivo | FIND-001/002 | `d01280a4b88531a4182776d61af959dc6ac63624f72d717286037c5384bb04f3` |
| `exploits/dearqa_exploit.py` | PoC exploit | FIND-001 | `514da6c0f4197d2af64225e3cae8bc47d1b5c88f245be2068291693014ed3979` |
| `exploits/grab_flag.py` | Script post-explotación | FIND-001 | `8fd47eab8aac211e2fb1c7e6694869399a8f4663814885066691613ea335ffaf` |
| `loot/user_flag.txt` | Flag (user) | FIND-001 | `9974880fe500d9b04479f6337cb16295b8e30c2821d9d7692f979be486d8a825` |

---

## 5. Remediation Summary

| Prioridad | Acción | Esfuerzo |
|----------|--------|----------|
| 1 (Quick win) | Acotar el input en `main` (`%31s` o `fgets`) | Low |
| 2 (Short term) | Recompilar con `-fstack-protector-all -pie -fPIE -z noexecstack -D_FORTIFY_SOURCE=2` | Low |
| 3 (Long term) | Eliminar función `vuln`/shell embebido; añadir pipeline de build con chequeo de mitigaciones | Medium |

**Validación post-remediación:** `checksec` debe mostrar `RELRO: Full`, `Canary: yes`, `NX: enabled`, `PIE: enabled`; y un payload de 48 B ya no debe desviar el flujo ni abrir shell.

---

## 6. Lessons Learned & Deviations

- **Descartes:** No se ejecutó `nmap`/web fuzzing: el binario provisto permitió análisis estático directo 
	(anti-patrón "spray and pray" evitado). OWASP no aplica (no es app web); MITRE ATT&CK se usó solo como overlay 
	de cadena de ataque.
- **Herramientas no disponibles en host:** `checksec`/`pwntools` ausentes → se usó `objdump`+`readelf`+Python 
	`socket`/`struct` (stdlib), suficiente para el objetivo.
- **Decisión táctica:** Se aprovechó la función "win" (`vuln`) en lugar de ret2libc/shellcode, porque el binario ya 
	la exponía y no hay ASLR/PIE — camino mínimo y fiable.
- **Nota de entorno:** La shell remota funcionó sobre el socket (socat/xinetd) leyendo de stdin; localmente `scanf` 
	adelanta el buffer y la shell no recibe comandos, pero el salto a `vuln` se confirmó igualmente.

### MITRE ATT&CK overlay (cadena de ataque, no clasificación de la vuln)
- **TA0001 Initial Access — T1190** Exploit Public-Facing Application (puerto 5700).
- **TA0002 Execution — T1203** Exploitation for Client Execution (`execve("/bin/bash")` vía BOF).
- **TA0004 Privilege Escalation — T1068** (pendiente, si se escala a root).
