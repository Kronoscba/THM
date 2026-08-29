# CTF collection Vol.1 — TryHackMe Writeup

## Resumen

20 challenges resueltos del room **CTF collection Vol.1** de TryHackMe.
Todos los flags siguen el formato `THM{flag}` salvo que se indique lo contrario.

---

### 1. Base64 Decode

**Texto:** `VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==`

**Herramienta:** `base64 -d`

```bash
echo "VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==" | base64 -d
```

**Flag:** `THM{ju57_d3c0d3_7h3_b453}`

---

### 2. Meta! (EXIF)

**Archivo:** `Find_me_1577975566801.jpg`

**Herramienta:** `exiftool`

```bash
exiftool Find_me_1577975566801.jpg
```

La flag estaba en el campo **Owner Name** de los metadatos EXIF.

**Flag:** `THM{3x1f_0r_3x17}`

---

### 3. Something is hiding (Steghide)

**Archivo:** `Extinction_1577976250757.jpg`

**Herramienta:** `steghide`

```bash
steghide extract -sf Extinction_1577976250757.jpg
# Passphrase: (vacío / Enter)
```

Extrae `Final_message.txt` con la flag.

**Flag:** `THM{500n3r_0r_l473r_17_15_0ur_7urn}`

---

### 4. QR Code

**Archivo:** `QR_1577976698747.png`

**Herramienta:** `zbarimg`

```bash
zbarimg QR_1577976698747.png
```

**Flag:** `THM{qr_m4k3_l1f3_345y}`

---

### 5. Hello Binary (Strings)

**Archivo:** `hello_1577977122465.hello` (ELF 64-bit)

**Herramienta:** `strings`

```bash
strings hello_1577977122465.hello | grep THM
```

La flag estaba visible en los strings del binario.

**Flag:** `THM{345y_f1nd_345y_60}`

---

### 6. Base58 Decode

**Texto:** `3agrSy1CewF9v8ukcSkPSYm3oKUoByUpKG4L`

**Herramienta:** Python

```python
import string
b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s = '3agrSy1CewF9v8ukcSkPSYm3oKUoByUpKG4L'
n = 0
for c in s: n = n * 58 + b58.index(c)
print(n.to_bytes((n.bit_length()+7)//8, 'big').decode())
```

**Flag:** `THM{17_h45_l3553r_l3773r5}`

---

### 7. ROT7 Caesar

**Texto:** `MAF{atbe_max_vtxltk}`

**Pista:** "13 is too mainstream" → no es ROT13, es ROT7.

**Flag:** `THM{hail_the_caesar}`

---

### 8. Make a comment (HTML)

**Pista:** "No downloadable file, no ciphered or encoded text."

La flag está en un comentario HTML o párrafo oculto (`display:none`) en la página del room.

**Flag:** `THM{4lw4y5_ch3ck_7h3_c0m3mn7}`

---

### 9. Corrupted PNG

**Archivo:** `spoil_1577979329740.png`

**Problema:** El header PNG estaba corrupto (`#3D_` en vez de `‰PNG`).

**Solución:** Reemplazar los primeros 4 bytes con la firma correcta `89 50 4E 47`.

```bash
python3 -c "
data = open('spoil.png', 'rb').read()
fixed = b'\x89\x50\x4E\x47' + data[8:]
open('spoil_fixed.png', 'wb').write(fixed)
"
```

Luego pasar OCR a la imagen reparada.

**Flag:** `THM{y35_w3_c4n}`

---

### 10. "lurking in the dark" (OCR)

**Archivo:** `dark_1578020060816.png`

**Técnica:** Píxeles casi negros (valor B=2,3 sobre fondo negro) formaban texto. Se realzó el contraste y se aplicó OCR.

```bash
tesseract dark_bright.png stdout
```

**Flag:** `THM{7h3r3_15_hOp3_1n_7h3_d4rkn355}`

---

### 11. Social Media (Reddit)

**Pista:** "Some hidden flag inside Tryhackme social account."

**Solución:** Buscar en el Reddit de TryHackMe (`r/tryhackme`).

**Flag:** `THM{50c14l_4cc0un7_15_p4r7_0f_051n7}`

---

### 12. Brainfuck

**Código:**
```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>++++++++++++++.------------.+++++.>+++++++++++++++++++++++.<<++++++++++++++++++.>>-------------------.---------.++++++++++++++.++++++++++++.<++++++++++++++++++.+++++++++.<+++.+.>----.>++++.
```

**Herramienta:** Intérprete Brainfuck en Python.

**Flag:** `THM{0h_my_h34d}`

---

### 13. XOR

**Strings:**
```
S1: 44585d6b2368737c65252166234f20626d
S2: 1010101010101010101010101010101010
```

**Solución:** XOR bit a bit.

```python
s1 = bytes.fromhex('44585d6b2368737c65252166234f20626d')
s2 = bytes.fromhex('1010101010101010101010101010101010')
result = bytes(a ^ b for a, b in zip(s1, s2))
```

**Flag:** `THM{3xclu51v3_0r}`

---

### 14. Exfiltrated ZIP

**Archivo:** `hell_1578018688127.jpg`

**Técnica:** ZIP oculto al final del JPEG (exfiltración). Contenía `hello_there.txt`.

```bash
python3 -c "
data = open('hell.jpg', 'rb').read()
idx = data.find(b'PK\x03\x04')
zip_data = data[idx:]
open('extracted.zip', 'wb').write(zip_data)
"
unzip extracted.zip
```

**Flag:** `THM{y0u_w4lk_m3_0u7}`

---

### 15. QR + SoundCloud

**Archivo:** `QRCTF_1579095601577.png`

**Solución:** QR → enlace a SoundCloud. El audio (text-to-speech) dice **"the flag is soundingqr"**.

**Flag:** `THM{SOUNDINGQR}`

---

### 16. Wayback Machine

**Target:** `https://www.embeddedhacker.com/` — 2 January 2020

**Solución:** Ver el snapshot en web.archive.org para esa fecha.

**Flag:** `THM{ch3ck_th3_h4ckb4ck}`

---

### 17. Vigenère (Uncrackable!)

**Texto cifrado:** `MYKAHODTQ{RVG_YVGGK_FAL_WXF}`
**Formato:** `TRYHACKME{FLAG IN ALL CAP}`

**Solución:** Se deduce la clave comparando el texto cifrado con el formato conocido `TRYHACKME{` → clave **THM** (se repite).

```python
cipher = "MYKAHODTQ{RVG_YVGGK_FAL_WXF}"
key = "THM"
result = ""
for c in cipher:
    if 'A' <= c <= 'Z':
        shift = ord(key[i % 3]) - ord('A')
        result += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
    else:
        result += c
```

**Flag:** `TRYHACKME{YOU_FOUND_THE_KEY}`

---

### 18. Decimal to ASCII

**Número:** `581695969015253365094191591547859387620042736036246486373595515576333693`

**Solución:** Convertir a hex y luego a ASCII.

```python
n = 581695969015253365094191591547859387620042736036246486373595515576333693
h = hex(n)[2:]
print(bytes.fromhex(h).decode())
```

**Flag:** `THM{17_ju57_4n_0rd1n4ry_b4535}`

---

### 19. PCAP Analysis (Neighbor's WiFi)

**Archivo:** `flag_1578026731881.pcapng`

**Solución:** Analizar con `tshark`. Se encontró un GET a `/flag.txt` con contenido en hex.

```bash
tshark -r flag.pcapng -Y "http" -T fields -e http.file_data
```

**Flag:** `THM{d0_n07_574lk_m3}`

---

## Herramientas utilizadas

| Herramienta | Propósito |
|---|---|
| `base64` | Decodificar Base64 |
| `exiftool` | Metadatos EXIF |
| `steghide` | Esteganografía JPEG |
| `zbarimg` | Decodificar QR |
| `strings` | Extraer strings de binarios |
| `tesseract` | OCR |
| `tshark` | Análisis de paquetes |
| `yt-dlp` | Descargar audio SoundCloud |
| `python3` | Scripting: decodificación, XOR, Vigenère, etc. |
| `unzip` | Extraer ZIPs |
