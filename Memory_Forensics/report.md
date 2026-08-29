# Memory Forensics — Informe de Investigación

**Caso:** Análisis de volcado de memoria del equipo de John (TryHackMe: Memory Forensics)
**Investigador:** Analista secundario (revisión post-análisis inicial en sitio)
**Fecha del informe:** 2026-06-17
**Metodología:** NIST SP 800-86 (Collection → Examination → Analysis → Reporting) + principios de integridad (hashing) y cadena de custodia.

---

## 1. Identificación y Alcance (Collection)

Se nos entregó un volcado de memoria RAM del equipo de John para reconstruir la línea de tiempo forense y recuperar artefactos relevantes del caso. El análisis se dividió en tareas:

| Tarea | Pregunta | Evidencia utilizada |
|-------|----------|--------------------|
| 2 | Password de John | `Snapshot6_1609157562389.vmem` (eliminado tras el análisis) |
| 3 | Último apagado + lo que John escribió | `Snapshot19_1609159453792.vmem` (eliminado tras el análisis) |
| 4 | Passphrase de TrueCrypt | `Snapshot14_1609164553061.vmem` (en custodia) |

**Evidencia en custodia (hash SHA-256):**
```
Archivo : content/Snapshot14_1609164553061.vmem
Tamaño  : 1073741824 bytes (1 GiB)
SHA-256 : 150b86d043ee1deeb374f3007a6baaeb71aeae15a16bedbd859d411dd5165e47
```
> Nota: los dumps de las tareas 2 y 3 fueron eliminados por el usuario tras su respectivo análisis; se documentan por nombre de archivo y hallazgos.

---

## 2. Examen (Examination)

**Herramientas:**
- Volatility 3 (`vol` 2.28.0) — identificación de SO, hashdump, registro.
- Volatility 2 (`phocean/volatility:latest`, Docker) — plugins `consoles` y `truecryptpassphrase` (vol3 no soporta Win7 en estos plugins).
- `john` + rockyou — cracking de hash NTLM.
- `strings -el` — barrido UTF-16 de la memoria.

**Identificación del sistema (Snapshot19):**
- SO: Windows 7 SP1 x64 (`NTBuildLab 7601.17514.amd64fre.win7sp1_rtm`)
- SystemTime del dump: `2020-12-27 23:06:01 UTC`

---

## 3. Análisis (Analysis)

### Tarea 2 — Password de John
- `vol windows.hashdump` → John (RID 1001): `47fbd6536d7868c873d5ea455f2fc0c9`
- Cracking NTLM con rockyou: **`charmander999`**

### Tarea 3 — Timeline y consola
- **Último apagado:** valor `ShutdownTime` en `SYSTEM\ControlSet001\Control\Windows` → **`2020-12-27 22:50:12 UTC`**
- **Lo que John escribió:** el plugin `consoles` (vol2) reveló la Command History de `conhost.exe` (PID 2488):
  ```
  Cmd #0: cd /
  Cmd #1: echo THM{You_found_me} > test.txt
  Cmd #2: cls
  Cmd #3: cd /Users
  Cmd #4: cd /John
  Cmd #5: dir
  Cmd #6: cd John
  ```
  La flag escrita por John fue **`THM{You_found_me}`** (respuesta del room: `You_found_me`).

### Tarea 4 — Passphrase TrueCrypt
- `vol2 --profile=Win7SP1x64 truecryptpassphrase` →
  `Found at 0xfffff8800512bee4 length 11: forgetmenot`
- Passphrase: **`forgetmenot`**

---

## 4. Reporte de Hallazgos (Reporting)

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 2 | Password de John | `charmander999` |
| 3a | Último apagado | `2020-12-27 22:50:12` |
| 3b | Lo que John escribió | `You_found_me` |
| 4 | Passphrase TrueCrypt | `forgetmenot` |

**Conclusión:** Se recuperaron con éxito las credenciales de la cuenta de John, la marca temporal del último apagado, la flag redactada en la consola y la passphrase del contenedor TrueCrypt, sin alterar la integridad de la evidencia (verificada por hash). Las imágenes intermedias fueron purgadas por el usuario una vez finalizado cada análisis.

---

## Apéndice — Comandos clave
```bash
# Identificación
vol -f <dump> windows.info

# Credenciales
vol -f <dump> windows.hashdump
john --format=NT --wordlist=rockyou.txt hashes.txt

# Consola (Win7 → vol2)
docker run --rm -v "$PWD/content":/data phocean/volatility \
  -f /data/Snapshot19_...vmem --profile=Win7SP1x64 consoles

# TrueCrypt (Win7 → vol2)
docker run --rm -v "$PWD/content":/data phocean/volatility \
  -f /data/Snapshot14_...vmem --profile=Win7SP1x64 truecryptpassphrase

# Integridad
sha256sum content/Snapshot14_1609164553061.vmem
```
