# Project HAVEABREAK — Informe de Investigación (Nodo CZ)

**Caso:** EC-2026-0847-CZ · TransEuro Logistics s.r.o. (Brno, CZ)
**Incidente:** Sustracción de 413.793 uds. de KITKAT (~12 t) en corredor Italia→Polonia, 26/03/2026
**Rol:** CZ Node Investigator (ECTA / Project HAVEABREAK)
**Tipo:** Investigación forense digital + OSINT (sin ataque a sistemas)

---

## 1. Metodología

**Ciclo de Inteligencia (CTI) aplicado a forense digital y OSINT**, estructurado en:

1. **Planificación / Requisitos** — Definir las preguntas del caso (VPN, estación, hora, denunciante, leaker).
2. **Recolección y preservación** — Inventariar evidencia (`content/`, ZIP del caso), verificar que el ZIP no estaba cifrado.
3. **Procesamiento y examen** — Forense de cada exhibición: cabeceras de correo, EXIF/OCR de imagen, CSV de logs y personal, export de comms.
4. **Análisis** — Correlación cruzada (IP→ASN, LOG→empleado, Gmail→hometown) y reconstrucción de línea de tiempo.
5. **Atribución OSINT** — Enriquecimiento externo (Google Maps) para recuperar la identidad completa del leaker.
6. **Diseminación** — Este informe y respuestas del caso.

Principios: cadena de custodia lógica, trazabilidad de cada conclusión a un artefacto, y separación entre **denunciante** (quien avisó) y **leaker** (quien filtró la ruta).

---

## 2. Evidencia analizada

| ID | Archivo | Tipo | Notas |
|----|---------|------|-------|
| Memo | `ecta_memo.html.pdf` | Briefing ECTA | Define exhibiciones y acciones por nodo |
| Exhibit A | `exhibit_a.eml` | Correo anónimo | Remitente `notmyname2847@gmail.com` → `redakce@novinybrno.cz` |
| Exhibit B | `exhibit_b.png` | Dashcam D1 | Sin metadatos GPS; analizada por OCR |
| Datos | `transeuro_data/employees.csv` | Personal | 15 empleados, sin columna de nombre |
| Datos | `transeuro_data/access_log.csv` | Logs de acceso | acciones VIEW/EDIT/EXPORT/AUTH_FAILED |
| Datos | `transeuro_data/comms_export.txt` | Mensajería interna | Exportada por BR-0255 bajo autoridad judicial |
| Contenedor | `ecta-case-1775237862109.zip` | Empaquetado | No cifrado; mismos archivos |

---

## 3. Análisis por fase

### 3.1 Exhibit A — Forense de correo electrónico
- **Origen IP:** `193.32.249.132` → whois `NET-31173-193-32-249-0-24` (descr "31173 Services AB infrastructure in Amsterdam, NL") → `AS39351 / 31173 Services AB` = **Mullvad VPN**.
- **Cliente:** `K-9 Mail for Android`; **TZ:** `+0100` (CET, coherente con salida NL en esa fecha).
- **Fecha envío:** 27/03/2026 23:14 CET.
- Conclusión: el denunciante ocultó su origen tras un nodo Mullvad (Ámsterdam) antes de enviar por Gmail.

### 3.2 Exhibit B — Forense de imagen
- EXIF: solo tamaño (1536×1024), **sin GPS**.
- OCR (tesseract, tras preproceso upscale/umbral): marca **ORLEN**, señal direccional **"Olomouc 27 km / Brno 45 km"**, precios diésel, overlay `26.03.2026 22:31:07`.
- Correlación: D1, salida ~258 (Kroměříž/Hulín); memo sitúa dashcam recuperada cerca de Hulín. Web corrobora: **ORLEN / Benzina — Kroměřížská 1281, 768 24 Hulín**.
- Conclusión: última vista del vehículo en ORLEN D1 (Hulín), coherento con ventana de tránsito Italia→Polonia.

### 3.3 Access log — Detección de anomalías
- `2026-03-24 07:11:03` **BR-0291** `ROUTE_IT_PL_Q1_2026.pdf` **AUTH_FAILED** → posterior `VIEW` → `2026-03-25 22:14:09` **EXPORT** (fuera de horario, noche previa a la salida del 26/03).
- `2026-03-27`: múltiples `ACCESS_DENIED` sobre `ROUTE_IT_PL` (cierre post-incidente).
- Conclusión: BR-0291 realizó_export_ anómalo que casa con la descripción del denunciante.

### 3.4 Comms — Análisis de comunicaciones
- `2026-03-24 09:11` BR-0255 avisa: Gmail externo **`kraliknovak09@gmail.com`** intentó acceder a la carpeta de rutas → **bloqueado**.
- "kralik" → **Králice** (ciudad natal de BR-0291 en `employees.csv`).
- BR-0312 (Dispatch) editó `DRIVER_SCHEDULE_WK13.xlsx` las noches 24 y 25/03 (quien monitoreaba la agenda).

### 3.5 Correlación con personal (`employees.csv`)
- **BR-0291** = Route Planner, Brno, **Králice nad Oslavou** → coincide con "kralik" del Gmail bloqueado y con el EXPORT anómalo.
- **BR-0312** = Dispatch Operator, Brno, Olomouc → denunciante (quien envió el tip anónimo).

### 3.6 Atribución OSINT (nombre del leaker)
- El nombre completo **no** estaba en los archivos del caso (CSV sin nombres; IČO censurado en el memo).
- Enriquecimiento externo (Google Maps) sobre el empleado BR-0291 / Králice nad Oslavou / TransEuro Brno → **Radovan Blšťák**.

---

## 4. Línea de tiempo

| Fecha/Hora | Evento | Fuente |
|------------|--------|--------|
| 24/03 07:11 | BR-0291 AUTH_FAILED en `ROUTE_IT_PL_Q1_2026.pdf` | access_log |
| 24/03 09:11 | Gmail `kraliknovak09` (Králice) bloqueado al acceder a rutas | comms |
| 24/03 23:41 | BR-0312 actualiza asignaciones WK13 | comms / access_log |
| 25/03 22:14 | BR-0291 EXPORT `ROUTE_IT_PL_Q1_2026.pdf` (fuera de horario) | access_log |
| 26/03 (mañana) | Vehículo sale de Italia | memo |
| 26/03 22:31 | Dashcam: vehículo en ORLEN D1 (Hulín) | Exhibit B |
| 27/03 23:14 | Correo anónimo (Mullvad) al periodista de Brno | Exhibit A |
| 28/03 | Nestlé confirma robo; ECTA emite assessment | memo |

---

## 5. Hallazgos (respuestas del caso)

1. **VPN usado en el correo anónimo:** **Mullvad** (AS39351 / 31173 Services AB, salida Ámsterdam).
2. **Dirección completa de la estación (Exhibit B):** **ORLEN (Benzina), Kroměřížská 1281, 768 24 Hulín, Rep. Checa** (D1, ~45 km Brno / ~27 km Olomouc).
3. **Hora de la acción sospechosa en el sistema de rutas (25/03/2026):** **22:14:09** (EXPORT por BR-0291).
4. **ID del empleado que envió el correo anónimo (denunciante):** **BR-0312**.
5. **Nombre completo del leaker:** **Radovan Blšťák** (BR-0291, Route Planner, Králice nad Oslavou) — recuperado por OSINT.

---

## 6. Conclusión

El caso es **insider-facilitated** (consistente con la evaluación ECTA). El empleado **BR-0291 / Radovan Blšťák** accedió y exportó la ruta IT-PL en horario anómalo la noche previa a la salida; el empleado **BR-0312** (Dispatch) detectó la actividad irregular y la denunció anónimamente tras ocultar su origen con Mullvad. La última ubicación conocida del vehículo es la estación ORLEN de Hulín en D1 a las 22:31 del 26/03.

---

## 7. Limitaciones
- El paquete de evidencia no incluyó staff records con nombres ni el IČO completo; el nombre del leaker requirió OSINT externo.
- Exhibit B carecía de metadatos geográficos; la identificación de la estación se apoyó en OCR + corroboración web.
- No se atacó ningún sistema; toda conclusión deriva de evidencia proporcionada y fuentes OSINT públicas.
