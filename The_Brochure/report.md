# Report — The Brochure (Hacker Holidays: Day 0 · OSINT)

## 1. Executive Summary

Room **The Brochure** (`hh-thebrochure-081f3e36`) es un reto puramente de OSINT. El objetivo fue
rastrear una pista oculta en la foto principal (hero photo) del brochure del *Byte Lotus Hotel*,
llegar a una cuenta de Instagram y, desde allí, a una cuenta oculta ("Vera la conserje") cuyas
publicaciones contenían fragmentos en Base64 que, descodificados y ordenados, revelan la flag.

- **Entorno**: TryHackMe (CTF autorizado / educativo).
- **Alcance**: análisis de imagen local + OSINT en redes sociales públicas.
- **Resultado**: flag obtenida — `THM{V3r@s_aCC0unt_h4s_b33n_f0und!}`
- **Riesgo global**: N/A (reto educativo de reconocimiento).

## 2. Methodology

Flujo seguido (adaptado de PTES → fase de *Intelligence Gathering* / OSINT):

1. **Análisis de la imagen** (`content/thebrochure.png`)
   - `file`, `exiftool`, `strings` → sin metadatos útiles (solo chunks PNG estándar: IHDR/sRGB/gAMA/pHYs/IDAT/IEND).
   - Inspección de chunks PNG con Python (struct) → sin `tEXt`/`zTXt`/`iTXt`.
   - Búsqueda de datos tras `IEND` → 0 bytes.
   - Esteganografía LSB (canal R) → sin texto legible.
   - **OCR (Tesseract)** del render ampliado → reveló texto visible en el diseño:
     `BYTE LOTU[S]`, `DATE MON JUL 27`, `Some things aren't posted. Some clues are.`,
     `VERA can assist you`, `Find us on Instagram ... with further information.`
2. **Localización de la cuenta del hotel** en Instagram (mencionada explícitamente en el brochure).
3. **Descubrimiento de la cuenta oculta**: entre los seguidores de la cuenta del hotel aparece
   *Vera la conserje* (la cuenta que el hotel "nunca quiso que miraras").
4. **Extracción de los fragmentos**: Vera publicó 3 posts con texto en Base64. Se tomaron 3
   capturas de pantalla (`content/2026-08-26_*.png`) y se extrajo el Base64 de cada una con OCR.
5. **Decodificación y ensamblaje**: se descodificó **cada fragmento por separado** y se concatenó
   el texto plano en el orden que produce una flag válida `THM{...}`, corrigiendo un carácter
   mal leído del OCR.

> Nota: el modelo no puede visualizar imágenes directamente, por lo que TODO el análisis de la
> foto (texto visible y fragmentos de las capturas) se hizo mediante **OCR (Tesseract)** sobre
> render ampliado, no a ojo.

## 3. Findings

### [FIND-001] Texto visible en el brochure apunta a Instagram + "VERA"
- **Severidad**: Info (pista OSINT)
- **Ubicación**: `content/thebrochure.png` (diseño gráfico)
- **Descripción**: El hero photo no lleva metadatos ocultos, pero el diseño expone la pista:
  "Find us on Instagram … VERA can assist you". Esto dirige la investigación a la red social.
- **Evidencia**: salida de `exiftool`/`strings` (sin metadata) + OCR del render.
- **Decisión**: seguir el rastro hacia la cuenta de Instagram del hotel.

### [FIND-002] Cuenta oculta "Vera la conserje"
- **Severidad**: Info (pista OSINT)
- **Ubicación**: seguidores de la cuenta de Instagram del *Byte Lotus Hotel*.
- **Descripción**: La cuenta de Vera contiene 3 publicaciones con fragmentos Base64.
- **Evidencia**: capturas `content/2026-08-26_18-43-58.png`, `..._18-44-39.png`, `..._18-44-46.png`.

### [FIND-003] Fragmentos Base64 → flag
- **Severidad**: Info (flag)
- **Ubicación**: 3 posts de la cuenta de Vera.
- **Fragmentos extraídos (OCR de cada captura) y decodificados**:

| Captura | Base64 (OCR) | Decodificado |
|---|---|---|
| `2026-08-26_18-43-58.png` | `VEhNelYzckBzX2FD` | `THM{V3r@s_aC` |
| `2026-08-26_18-44-39.png` | `QzB1bnRfaDRzX2lz` | `C0unt_h4s_is` |
| `2026-08-26_18-44-46.png` | `M25fZjB1bmQhfQ==` | `3n_f0und!}` |

- **Corrección aplicada**: el fragmento 2 decodifica a `..._is`, pero para completar la flag debe
  ser `..._b3`. En Base64, `_is` = `X2lz` y `_b3` = `X2Iz`: se corrigió el último carácter mal
  leído del OCR (`z` → `I`, confusión típica `I`/`l`/`z` en fuentes monoespaciadas).
- **Ensamblaje (orden correcto: frag1 + frag2 + frag3)**:

  ```
  THM{V3r@s_aC  +  C0unt_h4s_b3  +  3n_f0und!}
  = THM{V3r@s_aCC0unt_h4s_b33n_f0und!}
  ```

- **Flag**: `THM{V3r@s_aCC0unt_h4s_b33n_f0und!}`

## 4. Evidence Inventory

| Archivo | Tipo | Hallazgo | SHA256 |
|---|---|---|---|
| `content/thebrochure.png` | Imagen brochure (hero photo) | FIND-001 | `0d0fc9802ca86d449d32e6176d6389d374a34fec6472dbc5fc08b415a82c4fa2` |
| `content/2026-08-26_18-43-58.png` | Captura post Vera #1 | FIND-003 frag1 | `551d523ec8d1a02159deef5f82fcdeb23f4d8860a29d5d92406953a7524f56cc` |
| `content/2026-08-26_18-44-39.png` | Captura post Vera #2 | FIND-003 frag2 | `05f9c73451aeb6b7d628fb0d80a62b20b67671b25aa7f5f5c6e40cd1084905fa` |
| `content/2026-08-26_18-44-46.png` | Captura post Vera #3 | FIND-003 frag3 | `6d4c942725de6e1c1cc2fd6064a56084451cd30c063e5d3f079c883f22b85a2b` |

## 5. Remediation Summary

No aplica (reto CTF). Como lección de diseño: no incrustar pistas que vinculen una cuenta
"oficial" con una cuenta personal oculta mediante texto legible en imágenes públicas.

## 6. Lessons Learned & Deviations

- **Sin metadatos**: el brochure no escondía nada en EXIF/LSB; la pista era **visible en el diseño**.
  El error habitual habría sido forcejear con esteganografía; el OCR temprano ahorró tiempo.
- **Orden de fragmentos**: concatenar los Base64 y decodificar una sola vez funciona *solo* porque
  cada fragmento mide múltiplo de 4; el resultado seguía desordenado → hubo que decodificar por
  separado y reordenar.
- **OCR no es perfecto**: un solo carácter (`z` vs `I`) cambió `_is` por `_b3` y rompió la flag.
  Siempre validar contra una flag con formato `THM{...}` coherente.
- **Limitación de entorno**: el modelo no visualiza imágenes; todo el reconocimiento de texto
  dependió de Tesseract sobre el render ampliado.
