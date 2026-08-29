# Report — TryHackMe: Overheard at Breakfast

> **Classification:** OSINT / Reconnaissance Challenge
> **Author:** Security Assessment Agent (offensive security, authorized lab)
> **Date:** 2026-08-26
> **Target scope:** `0.0.0.0` (no live host — pure OSINT room). VPN callback context `192.168.134.200`.
> **Engagement type:** Authorized training lab (TryHackMe).

---

## 1. Executive Summary

An adversary (playing the role of a guest at the "Byte Lotus" resort) overheard a private conversation and captured a screenshot of a chat between two personas — **Ponzi** (an "Influencer & L3AK") and **Lambo!**. The conversation contained enough identifying detail to pivot from a leaked email address to a **hidden Gravatar profile** that the target believed had been wiped.

The assessment demonstrated that deleting a profile/account does **not** remove the publicly derivable artifacts tied to an email address. Gravatar keys profiles to the MD5 hash of the (lower-cased, trimmed) email, which is trivially computable by anyone who knows or guesses the address. The hidden profile exposed the target's real display name, physical location, and a base64-encoded flag.

| Item | Value |
|------|-------|
| **Global risk** | Informational (training lab) — but maps to a real-world **Account/Identity Disclosure** exposure |
| **Findings** | 1 (OSINT pivot to hidden account) |
| **Flag recovered** | `THM{S3creT_Pr0fil3_H4s_b3n_Id3nt1fi3d}` |
| **Time invested** | ~25 min (OCR + hash pivot + decode) |

---

## 2. Methodology (PTES-mapped)

| PTES Phase | Action taken | Evidence reference |
|------------|--------------|--------------------|
| **Pre-engagement** | Verified `.target` (`0.0.0.0`) and `.vpn` (`192.168.134.200`); confirmed this is an OSINT-only room (no host to attack). | `.target`, `.vpn` |
| **Intelligence Gathering** | Extracted conversation text from `content/conversation.png` via OCR (tesseract). | `notes/conversation_ocr.txt` |
| **Threat Modeling** | Identified the email `lambobytelotushotel@gmail.com` and the clue "free tool… upload profile… link media accounts… started with a **G**" as the pivot. Modeled the "G" tool as **Gravatar** (email-keyed profile). | `notes/conversation_ocr.txt` |
| **Vulnerability Analysis** | Computed `md5("lambobytelotushotel@gmail.com")` → `d4a5fc5d3128890778667e24617d7cc0`. Confirmed Gravatar exposes a public JSON profile at `https://en.gravatar.com/<hash>.json`. | `notes/gravatar_profile.json` |
| **Exploitation** | Retrieved Gravatar profile; parsed `aboutMe` field containing a base64 string. | `notes/gravatar_profile.json`, `notes/gravatar_avatar.bin` |
| **Post-Exploitation** | Base64-decoded the prize → recovered the room flag. | `loot/flag.txt` |
| **Reporting** | This document. | `report.md` |

**Decision framework applied:** The "G" tool was the only speculative link. It was validated (not assumed) by successfully resolving the Gravatar hash to a live profile whose `displayName` ("Lambo"), `currentLocation` ("Byte Lotus Hotel"), and email hash all corroborated the conversation — satisfying the agent's "verify before exploit" gate.

---

## 3. Findings

### [FIND-001] Hidden Gravatar account recoverable from leaked email (OSINT pivot)
- **Severity**: Informational (lab) / Medium (real-world identity disclosure)
- **CWE**: CWE-200 (Exposure of Sensitive Information) — indirect, via email-hash correlation
- **Location**: `https://en.gravatar.com/d4a5fc5d3128890778667e24617d7cc0.json`
- **Description**: The target disclosed their email in conversation. Gravatar derives profile identity from `MD5(lowercase(trim(email)))`, which is computable by any third party. The target believed they had "wiped everything," yet the Gravatar profile remained resolvable and exposed `displayName=Lambo`, `currentLocation=Byte Lotus Hotel`, username `cheerfullysongf28e3c3716`, and a hidden message/flag in the `aboutMe` field.
- **Evidence**:
  - File: `notes/conversation_ocr.txt` (lines showing email + "G" tool clue)
  - File: `notes/gravatar_profile.json` (live profile, HTTP 200)
  - Reproduction:
    ```bash
    EMAIL="lambobytelotushotel@gmail.com"
    HASH=$(printf '%s' "$EMAIL" | tr 'A-Z' 'a-z' | md5sum | awk '{print $1}')
    curl -s "https://en.gravatar.com/$HASH.json" | jq '.entry[0].aboutMe' -r | base64 -d; echo
    # -> THM{S3creT_Pr0fil3_H4s_b3n_Id3nt1fi3d}
    ```
- **Impact**: Correlation of a person's email to a persistent, deletable-in-name-only identity profile; location and alias disclosure; in a real engagement, a stepping stone for phishing/spear-phishing.
- **Remediation**:
  1. On Gravatar, explicitly set the profile to "private"/delete and remove linked accounts.
  2. Use a **separate, non-correlatable email** for Gravatar vs. primary/contact email to break the hash pivot.
  3. Treat any email shared in casual conversation as a permanent OSINT pivot.
- **References**:
  - Gravatar Developer Docs — avatar/profile hashing
  - OWASP OSINT resources

---

## 4. Evidence Inventory

| Archivo | Tipo | Hallazgo | SHA256 |
|---------|------|----------|--------|
| `content/conversation.png` | Screenshot de conversación (input del reto) | Fuente primaria de pistas | `659076e34aca6d55c81984be752affe12f0ffc465662ee40fefa96613018aa07` |
| `notes/conversation_ocr.txt` | Texto extraído por OCR (tesseract) | FIND-001 (email + pista "G") | `4728dbf26be8832451b2a23049af08bb5b5d251b04e6daa8cf90d9afe804492a` |
| `notes/gravatar_profile.json` | Perfil Gravatar resuelto (HTTP 200) | FIND-001 (displayName, ubicación, flag) | `fa8a8222fc1d3c839481cbd7204ba9e823db3d8c4c42e6e2db5d328b3005dd69` |
| `notes/gravatar_avatar.bin` | Avatar binario (HTTP 200, `?d=404`) | Corrobora existencia de perfil | `75869492558d623af27d576ca4dee899d66ed5af559047c14379f05b97ebe24c` |
| `loot/flag.txt` | Flag decodificada | FIND-001 (entrega) | `61feaa80aed6b2fee3e6ebe4be466a08ed007758f062642ba571eec3e5a598c4` |

---

## 5. Remediation Summary

| Prioridad | Acción | Esfuerzo |
|-----------|--------|----------|
| **Quick win** | Eliminar/ocultar el perfil Gravatar asociado al email y desvincular cuentas de media | Short term |
| **Short term** | Separar emails de Gravatar de emails de contacto/identidad para romper el pivote por hash | Short term |
| **Long term** | Política de higiene OSINT: asumir que cualquier email compartido es un pivote permanente; awareness para personal con presencia pública | Long term |

**Validación post-remediación:** tras la limpieza, `curl https://en.gravatar.com/<hash>.json` debe retornar `{"entry":[]}` o 404, y el hash ya no debe resolver a un perfil con datos.

---

## 6. Lessons Learned & Deviations

- **Vectores descartados:** No se realizó escaneo de red (`.target`=0.0.0.0 confirma room de OSINT, sin host). No se asumió "GitHub" ni "Linktree" para la pista "G"; se validó Gravatar resolviendo el hash a un perfil coherente con la conversación.
- **Herramientas que no funcionaron / notas:** El `read` nativo de imagen no pudo mostrar `conversation.png` (modelo text-only) → se usó `tesseract` OCR como proxy. La ruta `en.gravatar.com/<hash>` (sin `.json`) retorna 302 redirect; el endpoint JSON es el canónico.
- **Decisiones tácticas:** El pivote email→MD5→Gravatar fue la ruta más corta y de menor ruido; el campo `aboutMe` contenía el premio en base64, no el username ni la ubicación.
- **Reproducibilidad:** Cualquier auditor siguiendo la sección 2 y el comando de reproducción en FIND-001 llega al mismo flag.
