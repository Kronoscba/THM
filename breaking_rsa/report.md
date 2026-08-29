# Report — breakrsa (TryHackMe, "Breaking RSA")

## 1. Executive Summary
- **Authorized scope**: TryHackMe room `breakrsa`, target `10.67.181.157` (VPN tunnel `.vpn` = 192.168.134.200). Date: session 2026-08-28.
- **Outcome**: Full `root` compromise via recovery of the RSA private key used for SSH.
- **Critical findings**: (1) RSA key generated with two primes `p`,`q` extremely close together → trivially factorable by Fermat's method; (2) direct `root` SSH login enabled with that key.
- **Global risk**: **Critical**.
- **Time invested**: ~15 min active.

## 2. Methodology (PTES)
- **Pre-engagement**: context files `.target`/`.vpn` verified; tun0 up (§20).
- **Intelligence Gathering**: `rustscan` + `nmap -sV` → 22/ssh, 80/http. (`nmap/rustscan_initial.*`)
- **Threat Modeling**: web app likely exposes keys/logs; tracked SSH-root as goal.
- **Vulnerability Analysis**: `gobuster` on `/` → `/development/`; retrieved `id_rsa.pub` + `log.txt` stating weak prime selection. (`web/gobuster_dir.txt`, `content/`)
- **Exploitation**: Fermat factorization of modulus `n` → `p`,`q`; reconstructed private exponent `d`; forged PEM key. (`exploits/rsa_break.py`, `loot/private_key.pem`)
- **Post-Exploitation**: `ssh root@target -i loot/private_key.pem` → uid=0; read flag. (`evidence/root_access.txt`)
- **Reporting**: this document.

## 3. Findings

### [FIND-001] Weak RSA key generation (Fermat-factorable)
- **Severity**: Critical
- **CWE**: CWE-320 (Key Management Errors) / CWE-331 (Insufficient Entropy)
- **Location**: `http://10.67.181.157/development/id_rsa.pub`
- **Description**: The SSH host/user key was generated with two primes `p` and `q` whose difference is tiny. For RSA, `n = p*q`; when `p ≈ q`, `n` is a near-square and Fermat's factorization converges instantly.
- **Evidence**:
  - `content/log.txt`: "The two randomly selected prime numbers (p and q) are very close to one another... broken with Fermat's factorization method."
  - `exploits/rsa_break.py` output: `p` and `q` differ only in their final digits; `p*q == n` asserted.
- **Impact**: Full private-key recovery → unauthorized root access.
- **Remediation**: Use a CSPRNG with sufficient entropy; never let `|p−q|` be small. Standard libraries (OpenSSL) already guarantee this; replace the faulty key-generation library. Rotate the compromised key and all credentials.

### [FIND-002] SSH root login with recovered key
- **Severity**: Critical
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)
- **Location**: `10.67.181.157:22` (sshd, PermitRootLogin enabled)
- **Description**: Root login over SSH is permitted and the root key was the weak RSA key above.
- **Evidence**: `evidence/root_access.txt` → `uid=0(root)`.
- **Impact**: Direct privileged shell.
- **Remediation**: Disable `PermitRootLogin`; use least-privilege accounts + sudo; enforce key strength.

## 4. Evidence Inventory
| File | Type | Finding | SHA256 |
|------|------|---------|--------|
| `nmap/rustscan_initial.nmap` | Port scan | Recon | b06d9ebba7072945849c75f51ce6389145b4547ceff39fe272344146818d8933 |
| `web/gobuster_dir.txt` | Dir brute | Discovery | (see host) |
| `content/id_rsa.pub` | Public key | FIND-001 | b8a0db32c481a39731ad8d270fa34c4dfe7756aca51d94dda9e6aa901dcbeb9f |
| `content/log.txt` | Note | FIND-001 | 708431883146bc8e75a45d026f1c90f1aa57ee40570b69a702dce7d032ba9cde |
| `exploits/rsa_break.py` | Exploit | FIND-001 | 3b1d140e3544a691df4489179504209175938920d9c29390c998609f51397d95 |
| `loot/private_key.pem` | Private key | FIND-001/002 | b3d2279b991d8846850e8851f2848a8e4ef2efbd9e3412a6d3c1c95f3bbae9a4 |
| `loot/root_flag.txt` | Flag | — | 4d0254cfc868f9d8acbe34c5ff3fb44e0b28310f5be0c0c94f29b5eb64d3feab |
| `evidence/root_access.txt` | Proof | FIND-002 | 3cb9b148ed0d90399b7040ede532860e0e003afa57448beeb3257ced2faf56fe |

## 5. Remediation Summary
1. **(Quick win)** Disable `PermitRootLogin` and rotate the SSH host key (it is compromised).
2. **(Short term)** Replace the vulnerable RSA key-generation library; regenerate all keys with strong entropy.
3. **(Validation)** Re-scan: confirm no Fermat-factorable modulus (|p−q| large) and root login refused.

## 6. Lessons Learned & Deviations
- `httpx` on this host rejects `-u` (positional URL required) — minor tooling difference vs AGENTS.md §5.
- This instance's hidden dir is `/development/` (writeups redact it).
- Fermat factorization needed only `math.isqrt` (stdlib); `gmpy2` not required.
