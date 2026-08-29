# Reconocimiento

- Werkzeug 3.0.1 / Python 3.12.3
- `/` landing de marketing
- `/survey` form POST -> 302 a `/`, cookie `session` (Flask SecureCookieSession)
- `/login` admin login (solo redirige si no autenticado)
- `/admin` y `/admin/submissions` -> 302 a `/login`
- `/static/css/style.css` solo CSS estático
- Sin robots.txt, sitemap, .git, .env

# Señales de la room

- "No algorithms. No AI. Just real humans" -> ironía: lo procesa un LLM/headless browser
- "Our matchmaking team reads every word" -> input del survey es renderizado y ejecutado en navegador del admin
- "Within a minute" -> trigger asíncrono

# Flag

`THM{XSS_CuP1d_Str1k3s_Ag41n}` (base64 de `flag=...`)

# Vector

Stored XSS en el form del survey. El admin que abre la página de submissions
ejecuta el `<script>` en su navegador y `fetch` exfiltra `document.cookie`.