# Session Notes — breakrsa (Breaking RSA)

- **Target**: 10.67.181.157 (from `.target`) | **Callback/VPN**: 192.168.134.200 (from `.vpn`, tun0 up)
- **Room type**: Crypto + web recon → RSA private key recovery → SSH root.
- **Authorized scope**: TryHackMe training lab (per AGENTS.md §1).

## Timeline
1. Env verification (§20): 4 cores / 7.7 GB, tun0 active, tools OK. Created missing dirs (web, loot, ad, evidence).
2. rustscan → 22/ssh (OpenSSH 8.2p1), 80/http (nginx 1.18.0). Saved nmap/rustscan_initial.*.
3. httpx probe (this build uses positional URL, not `-u`). curl confirmed landing page "Jack Of All Trades".
4. gobuster dir (seclists common.txt) → `/development/` (301). Saved web/gobuster_dir.txt.
5. /development/ autoindex → id_rsa.pub (725B), log.txt (321B). Downloaded to content/.
6. log.txt: p,q "very close" → Fermat factorization; SSH root login enabled.
7. exploits/rsa_break.py: parse n,e → Fermat → p,q (differ only in last digits) → forge PEM → loot/private_key.pem.
8. ssh root@10.67.181.157 -i loot/private_key.pem → root shell → flag `breakingRSAissuperfun20220809134031`.

## Flags
- root: `breakingRSAissuperfun20220809134031` (loot/root_flag.txt)
- user: none present on target.
