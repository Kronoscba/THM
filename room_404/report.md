# Byte Lotus — Guest Experience Platform

## 1. Executive Summary

| Field | Detail |
|-------|--------|
| **Target** | `10.67.144.120:8080` (HTTP/Werkzeug) |
| **Date** | 2026-08-26 |
| **Type** | CTF Lab — TryHackMe |
| **Risk Global** | **High** — Exposed `.git` directory leaks source code and staging credentials |
| **Flags Found** | 1 (`THM{byt3_l0tus_n3v3r_f0rg3ts}`) |
| **Time Total** | ~10 min |

### Resumen ejecutivo (negocio)

El servidor de la plataforma "Byte Lotus" tenía el repositorio Git completo expuesto vía HTTP. Esto permite a cualquier visitante descargar el código fuente completo, incluyendo una bandera de staging (flag) que fue retirada antes del lanzamiento. La exposición del `.git` es una falla de configuración del servidor web que podría haber filtrado credenciales, secretos o lógica de negocio en producción.

---

## 2. Methodology

### Fases PTES aplicadas

| Fase PTES | Acción realizada | Archivo de evidencia |
|-----------|-----------------|---------------------|
| **Pre-engagement** | Verificación de `.target` (IP) y `.vpn` (callback). Confirmación de scope. | `.target`, `.vpn` |
| **Intelligence Gathering** | RustScan inicial → puertos 22/tcp (SSH OpenSSH 9.6p1) y 8080/tcp (Werkzeug 3.0.1 Python 3.12.3). | `nmap/rustscan_initial.*` |
| **Threat Modeling** | Servicio web en 8080 → posible Flask/Werkzeug dev server. Hipótesis: exposición de código fuente o debug endpoint. | — |
| **Vulnerability Analysis** | FFuzzing de directorios con SecLists `common.txt` → detectado `.git` expuesto. | `web/ffuf_initial.json` |
| **Exploitation** | Dump del repositorio Git con `git-dumper` → recuperación completa del código fuente. | `content/repo/` |
| **Post-Exploitation** | Extracción de flag desde `README.md`. | `loot/flag.txt` |
| **Reporting** | Este documento. | `report.md` |

### Herramientas utilizadas

| Herramienta | Versión/Paquete | Uso |
|-------------|-----------------|-----|
| `rustscan` | v3.x | Enumeración rápida de puertos |
| `nmap` | 7.991 | Detección de servicios (via rustscan) |
| `ffuf` | latest | Fuzzing de directorios |
| `git-dumper` | 1.0.9 | Descarga de repositorio `.git` expuesto |
| `curl` | — | Verificación manual de archivos |

---

## 3. Findings

### [FIND-001] Repositorio Git expuesto en directorio web

| Campo | Valor |
|-------|-------|
| **Severidad** | **High** |
| **CVSS 3.1** | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **CWE** | CWE-538 (Insertion of Sensitive Information into Externally-Accessible File or Directory) |
| **Ubicación** | `http://10.67.144.120:8080/.git/` |
| **Descripción** | El directorio `.git` del repositorio de código fuente está accesible públicamente vía el servidor web Werkzeug. Esto permite descargar el historial completo de commits, el código fuente, y cualquier credencial o secreto que haya sido commiteado. |
| **Evidencia** | |
| Fuzzing | `web/ffuf_initial.json` — Rutas detectadas: `.git`, `.git/HEAD`, `.git/index`, `.git/config`, `.git/logs/` |
| Dump exitoso | `content/repo/` — Archivos recuperados: `README.md`, `app.js`, `index.html` |
| Flag extraída | `loot/flag.txt` — `THM{byt3_l0tus_n3v3r_f0rg3ts}` |
| **Impacto** | Exposición completa del código fuente. En un entorno real, esto podría filtrar credenciales de base de datos, tokens de API, lógica de negocio propietaria, y hashes de autenticación. |
| **Remediación** | Configurar el servidor web para bloquear el acceso a directorios ocultos (`.git`, `.env`, `.DS_Store`). Ejemplo con Werkzeug/Nginx: `location ~ /\. { deny all; }`. Eliminar el repositorio de la carpeta pública de producción. |

---

## 4. Evidence Inventory

| Archivo | Tipo | Hallazgo relacionado | SHA256 |
|---------|------|---------------------|--------|
| `nmap/rustscan_initial.nmap` | Port scan | Reconocimiento inicial | `d42f8958f45e71d38f987e02f4d6c56b6c2be83797e3ca0c74227b1ee31c77a3` |
| `nmap/rustscan_initial.gnmap` | Port scan (grepable) | Reconocimiento inicial | `aaa34a449bedb3291a23f4c4ea9cc7a3c2740c1c4f489f415ec9864e7616e5d0` |
| `nmap/rustscan_initial.xml` | Port scan (XML) | Reconocimiento inicial | `f9bdda135e7bf2642e9364ef88d01b9f860b707da46440347d9a065115d2e4c0` |
| `web/ffuf_initial.json` | Web fuzzing | Descubrimiento de `.git` | `b0dd70efdcc8e69f13f66755d0314ebb59a251a08c8ec8e4624c1af5a82191c2` |
| `content/repo/README.md` | Código fuente | Flag de staging | `c1940e7eb1d42dda362c0f1fb32e8c60e2c2d507d5d73626f8fb5de76594970e` |
| `content/repo/app.js` | Código fuente | Front-end stub | — |
| `content/repo/index.html` | Código fuente | Página principal | — |
| `loot/flag.txt` | Flag | Flag THM | `76470336475192e5d88fd42451609b1466e93892bd42887bc72f4fbc267c41c7` |

---

## 5. Remediation Summary

| Prioridad | Acción | Esfuerzo |
|-----------|--------|----------|
| **Quick win** | Agregar regla en el servidor web para bloquear acceso a `.git` y otros directorios ocultos | 5 min |
| **Short term** | Auditar la carpeta de despliegue para eliminar archivos que no deben estar en producción (`.git`, `.env`, backups) | 1 hora |
| **Long term** | Implementar pipeline CI/CD que publique solo artefactos compilados, nunca el repositorio completo | 1 día |

### Validación post-remediación

```bash
# Verificar que .git ya no es accesible
curl -s -o /dev/null -w "%{http_code}" http://TARGET:8080/.git/HEAD
# Resultado esperado: 403 o 404
```

---

## 6. Lessons Learned & Deviations

- **Puerto 22 (SSH)** detectado pero no explotado — sin credenciales y no relevante para el objetivo del lab.
- **No se intentó fuerza bruta** contra SSH (siguiendo principios del agent: "nunca spray and pray").
- **`git-dumper`** fue más eficiente que `wget` recursivo para la recuperación del repositorio, ya que reconstruye objetos Git directamente.
- **El flag estaba en texto plano** en `README.md` — en un escenario real, este tipo de secretos en repositorios es una de las principales fuentes de filtración de credenciales.

---

*Generado por el agente de pentesting — 2026-08-26*
