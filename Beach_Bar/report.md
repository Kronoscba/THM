# Beach Bar — MITRE ATT&CK TTP Mapping Report

| | |
|---|---|
| **Lab** | Beach Bar (author: Byte Lotus) |
| **Platform** | TryHackMe |
| **Target** | `10.64.132.157` |
| **Engagement type** | Authorized CTF / offensive exercise |
| **Framework** | MITRE ATT&CK® Enterprise (v15) |
| **Outcome** | Full compromise: `bartender` (low) → `root`. Both flags captured. |

---

## 1. Executive Summary

The target exposed a Flask "jukebox" web application on TCP/80. The adversary emulated the following ATT&CK tactics to reach root:

- **Reconnaissance** — port/service discovery.
- **Initial Access** — exploit of a public-facing app (unsafe YAML deserialization → RCE) and use of valid (default/demo) accounts.
- **Credential Access** — recovery of unsecured credentials (login comment in HTML source; clear-text streaming password in process command line).
- **Execution** — Python and Unix shell command execution through deserialization.
- **Discovery** — enumeration of users, processes, host info, and files.
- **Privilege Escalation** — reuse of valid credentials to move from `bartender` to `root`.

---

## 2. ATT&CK Technique Mapping (Navigator View)

| Tactic | Technique | ID | Sub-ID | Procedure (observed) |
|---|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | — | `rustscan`/`nmap` identified 22/80. |
| Reconnaissance | Gather Victim Host Information | T1592 | — | OS/version and service banner enumeration. |
| Initial Access | Exploit Public-Facing Application | T1190 | — | Unsafe `yaml.load(Loader=yaml.Loader)` in `/import`. |
| Initial Access | Valid Accounts | T1078 | .001 (Default) | Logged in with `dj:dj` (demo creds). |
| Credential Access | Unsecured Credentials | T1552 | .001 | Creds in HTML comment; stream-pass in `ps` cmdline. |
| Execution | Command and Scripting Interpreter | T1059 | .006 / .004 | Python `yaml` object apply + `bash -c`. |
| Discovery | System Owner/User Discovery | T1033 | — | `id`, `groups`. |
| Discovery | Process Discovery | T1057 | — | `ps aux` revealed root `jukeboxd` + `--stream-pass`. |
| Discovery | System Information Discovery | T1082 | — | `uname -a`, OS release. |
| Discovery | File and Directory Discovery | T1083 | — | `ls`/`find` for flag files. |
| Discovery | Account Discovery | T1087 | .001 | Local account enumeration. |
| Privilege Escalation | Valid Accounts | T1078 | — | `su root` with reused streaming password → root. |

---

## 3. Detailed Techniques

### T1595 — Active Scanning  *(Reconnaissance)*
- **Procedure**: `rustscan` against `10.64.132.157` returned `22/tcp` (OpenSSH 9.6p1) and `80/tcp` (Gunicorn/Flask). Follow-up `nmap` confirmed service banners.
- **Detection**: External scan alerts; rate/volume baselining on edge sensors.
- **Mitigation**: M1056 (Network Intrusion Prevention); M1031 (Network Segmentation).

### T1592 — Gather Victim Host Information  *(Reconnaissance)*
- **Procedure**: Identified Ubuntu 24.04, Flask/Gunicorn stack, and auth flow (`/` → `/login` → `/dashboard` → `/import`).
- **Mitigation**: M1056; reduce version/banner disclosure (M1041 — do not reveal build info).

### T1190 — Exploit Public-Facing Application  *(Initial Access)*
- **Procedure**: `/import` parses the `playlist` field with `yaml.load(content, Loader=yaml.Loader)`. The full loader enables arbitrary Python object construction.
  Payload:
  ```yaml
  !!python/object/apply:subprocess.check_output
  - ["bash", "-c", "id; cat /home/bartender/user.txt; true"]
  ```
  Output rendered in a `<pre>` block → **RCE as `bartender` (uid 1001)**.
- **Why it worked**: `yaml.Loader` instantiates Python objects/apply tags from attacker-controlled input.
- **Detection**: EDR/parent-child monitoring of `gunicorn` spawning `bash`/`python` shells; WAF rules for YAML object tags (`!!python/`).
- **Mitigation**: M1050 (Exploit Protection); **replace `yaml.load` with `yaml.safe_load`**; input schema validation (M1041).

### T1078 — Valid Accounts  *(Initial Access → Privilege Escalation)*
- **Sub-technique (.001 Default Accounts)**: Authenticated to the app with `dj:dj` found in a hidden HTML comment (`USERS = {"dj":"dj"}` in `app.py`).
- **Privilege Escalation**: The stream backend password (`SunsetSpritz2024!`), recovered from the root `jukeboxd` process command line, was **reused as the `root` account password**:
  ```bash
  echo 'SunsetSpritz2024!' | su - root -c 'id; cat /root/root.txt'
  # uid=0(root) gid=0(root) groups=0(root)
  # THM{cr3d3nt14l_r3us3_4t_th3_b34ch_b4r}
  ```
- **Detection**: Impossible-travel / logon anomaly monitoring; alert on `su`/`sudo` to root from service accounts; credential-stuffing detection.
- **Mitigation**: M1027 (Password Policy); M1013 (Application Developer Guidance — no shared/reused secrets); M1018 (User Account Management — unique per-service credentials).

### T1552 — Unsecured Credentials  *(Credential Access)*
- **Sub-technique (.001 Credentials In Files)**: Demo credentials embedded in an HTML source comment on `/login` and hard-coded in `app.py`.
- **Additional exposure**: Clear-text secret passed as a command-line argument (`--stream-pass SunsetSpritz2024!`) to a **root** process, readable via `/proc/<pid>/cmdline` and `ps`.
- **Detection**: Secret scanning in source/repo; monitoring for secrets in process command lines (e.g., `auditd` execve logging).
- **Mitigation**: M1051 (Principle of Least Privilege); M1027; load secrets from permission-restricted files or a secrets manager, never argv.

### T1059 — Command and Scripting Interpreter  *(Execution)*
- **.006 Python**: `yaml` object/apply construct executed `subprocess.check_output`.
- **.004 Unix Shell**: `bash -c "<cmd>"` executed the arbitrary command.
- **Detection**: Process lineage from the web server to shell interpreters; allow-listing.
- **Mitigation**: M1049 (Antivirus/Antimalware); M1038 (Execution Prevention — disable dangerous interpreters for the service account).

### T1033 — System Owner/User Discovery  *(Discovery)*
- **Procedure**: `id`, `groups` to confirm `bartender` context and group membership.

### T1057 — Process Discovery  *(Discovery)*
- **Procedure**: `ps aux` revealed `jukeboxd.py` running as **root** (PID 617) with `--stream-pass SunsetSpritz2024!` — the pivot to privilege escalation.
- **Detection**: Auditd `execve` of `ps`/`top` from service accounts; command-line secret exposure alerts.

### T1082 — System Information Discovery  *(Discovery)*
- **Procedure**: `uname -a`, `/etc/os-release` → Ubuntu 24.04, kernel `7.0.0-1009-aws`.

### T1083 — File and Directory Discovery  *(Discovery)*
- **Procedure**: `ls -la /home/bartender /home/ubuntu /`, `find / -name '*.txt'` to locate flag files.

### T1087.001 — Account Discovery: Local Account  *(Discovery)*
- **Procedure**: `id`/`groups` and inspection of `/home` to enumerate `bartender` and `ubuntu` accounts.

---

## 4. Indicators & Objectives

| Type | Location | Value |
|---|---|---|
| **User flag** | `/home/bartender/user.txt` | `THM{y4ml_pl4yl1st_pwns_th3_b34ch}` |
| **Root flag** | `/root/root.txt` | `THM{cr3d3nt14l_r3us3_4t_th3_b34ch_b4r}` |
| Credential (demo) | `/login` HTML comment | `dj:dj` |
| Credential (root) | `jukeboxd` cmdline | `SunsetSpritz2024!` (reused as root password) |

---

## 5. Attack Path (narrative)

```
[Recon] T1595/T1592
   └─ Ports 22/80, Flask app
[Initial Access] T1190 + T1078(.001)
   ├─ YAML deserialization RCE in /import        (T1059.006/.004, T1190)
   └─ Login with dj:dj from HTML comment         (T1078.001)
[RCE] as bartender (uid 1001)
[Discovery] T1033/T1057/T1082/T1083/T1087
   └─ ps aux → root jukeboxd + stream-pass        (T1057, T1552)
[Credential Access] T1552
   └─ stream-pass recovered from cmdline
[Privilege Escalation] T1078
   └─ su root with reused password → root        (root flag)
```

---

## 6. Recommendations (mapped to Mitigations)

1. **Eliminate unsafe YAML deserialization** (T1190/T1059 → M1050, M1041): use `yaml.safe_load()`; validate schema; never deserialize user input with `yaml.Loader`.
2. **Stop credential reuse** (T1078/T1552 → M1027, M1013, M1018): unique, strong passwords per account/service; prefer key-based or passwordless auth for services.
3. **Protect secrets** (T1552 → M1051): remove creds from source/HTML; never pass secrets via `argv` (use files with 0600 perms or a secrets manager); scan repos and monitor process command lines.
4. **Least privilege** (T1078 escalation → M1018): run `jukeboxd` as a dedicated non-root user; restrict `su`/`sudo` for service accounts; enable PAM controls.
5. **Detection engineering** (all): alert on web-server→shell process lineage, YAML object tags at the WAF, and `su`/`sudo` to root from service accounts; enable `auditd` execve logging.

---

*Authorized offensive exercise. No out-of-scope systems were touched; host integrity was preserved beyond reading the objective flags.*
