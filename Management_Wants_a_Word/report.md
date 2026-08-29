# Management Wants a Word — Reporte Forense

**Room:** TryHackMe — Management Wants a Word (forensics)
**Tipo:** Investigación forense de imagen Windows (KAPE). Sin explotación, solo análisis de artefactos.
**Alcance:** Autorizado (CTF/entrenamiento). Equipo objetivo: laptop dejada en la habitación 214, invitada "Vera".

---

## 1. Metodología

Se aplicó el ciclo forense estándar (NIST SP 800-86 / modelo **Adquirir → Preservar → Analizar → Reportar**), orientado a recuperación de credenciales y análisis de contenedor cifrado:

1. **Preservación:** trabajo sobre copia de la imagen KAPE; montaje del contenedor en modo *solo lectura* para no alterar evidencia.
2. **Reconocimiento:** enumeración del perfil del usuario `vera` y sus artefactos (navegador, credenciales, documentos).
3. **Recuperación de credenciales:** extracción de secretos desde DPAPI (Chrome Login Data) y LSA Secrets (registry) usando la contraseña de sesión de Windows.
4. **Identificación del contenedor:** reconocimiento del formato del archivo `backup` y validación como volumen VeraCrypt.
5. **Apertura y extracción:** montaje del volumen con la clave recuperada y análisis del documento objetivo.
6. **Análisis de evidencia:** renderizado del PDF y OCR para recuperar la flag.
7. **Limpieza:** desmontaje y cierre del mapper; borrado de artefactos temporales creados.

---

## 2. Entorno y herramientas

- Imagen: KAPE Windows 10/11 de `C:\Users\vera\`
- `sqlite3` — lectura de bases Chrome (History, Login Data)
- `pypykatz dpapi` — descifrado de masterkey DPAPI y blob de Chrome
- `secretsdump.py` (Impacket) — volcado de LSA Secrets / SAM / SYSTEM
- `cryptsetup` (`--type tcrypt --veracrypt`) — identificación y montaje del contenedor
- `pdftoppm`, `tesseract`, `exiftool`, `pdfinfo` — análisis del PDF

---

## 3. Hallazgos

### 3.1 Usuario y contexto
- Usuario: `vera` — SID `S-1-5-21-2529683458-431225740-1723070931-1000`
- Historial Chrome relevante: búsquedas de "exfiltrate data red teaming", "chrome cves" y el portal `http://bytelotus.thm:8080/` (SecureVault / login).

### 3.2 Contraseña de sesión de Windows (LSA Secrets)
- `secretsdump.py -system SYSTEM -sam SAM -security SECURITY LOCAL`
- `DefaultPassword (Unknown User): minivera`

### 3.3 Credencial de Chrome (DPAPI)
- Login Data → origen `http://bytelotus.thm:8080/login`, usuario `VeraSecretVault`.
- Masterkey DPAPI descifrada con la contraseña `minivera`.
- **Contraseña recuperada:** `Wh4t1sV3raD0inG0nTh1sH0st`

### 3.4 Contenedor cifrado `backup`
- Ruta: `C:\Users\vera\Documents\backup` (100 MiB, 104857600 bytes).
- Identificado como **VeraCrypt v5** vía `cryptsetup tcryptDump --veracrypt`:
  - PBKDF2: `sha512` · Cifrado: `aes` · Modo: `xts-plain64` · Clave: 512-bit · Sector: 512 · MK offset: 131072.
- Apertura con la clave `Wh4t1sV3raD0inG0nTh1sH0st` (montaje read-only).

### 3.5 Documento y flag
- Volumen contiene `secret_financial_documents/important_invoice_byte_lotus.pdf` (27 kB, 1 página, sin cifrar).
- La flag está como **texto en imagen** dentro del PDF (no como texto seleccionable).
- Render (`pdftoppm`) + OCR (`tesseract`):
  - `INVOICE BYTE LOTUS RESORTS ... 1. Flag: THM{1t_w4s_V3r4_A11_Al0ng?!}`

**FLAG:** `THM{1t_w4s_V3r4_A11_Al0ng?!}`  → *"it was Vera all along?!"*

---

## 4. Cadena de custodia / artefactos

| Artefacto | Ubicación | Hallazgo |
|---|---|---|
| LSA Secrets | `SECURITY` | `minivera` |
| Chrome Login Data | `...\Google\Chrome For Testing\User Data\Default\Login Data` | `Wh4t1sV3raD0inG0nTh1sH0st` |
| Contenedor | `C:\Users\vera\Documents\backup` | VeraCrypt v5 |
| PDF | `secret_financial_documents/important_invoice_byte_lotus.pdf` | flag (OCR) |

---

## 5. Limpieza realizada
- `sudo umount /mnt/vc`
- `sudo cryptsetup close vc_blind`
- `sudo rmdir /mnt/vc`
- Verificado: `/mnt/vc` inexistente y `vc_blind` inactivo.
- Flag persistida en `flag.txt` (copia de trabajo, fuera de la evidencia original).

---

## 6. Conclusión
La "contraseña que Vera no quiso dejar" era la clave de su vault de Chrome (`Wh4t1sV3raD0inG0nTh1sH0st`), que a su vez abría el contenedor VeraCrypt `backup`. Dentro, un PDF camuflado como factura contenía la flag como imagen. El acceso se logró íntegramente por análisis forense de artefactos Windows + DPAPI, sin actividad ofensiva.
