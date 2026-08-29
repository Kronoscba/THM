#!/usr/bin/env python3
# Interact with FreeSWITCH mod_event_socket
# uso: fs_socket.py <IP> <PORT> <cmd> [password]
import socket, sys, time, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
cmd = sys.argv[3] if len(sys.argv) > 3 else "api status"
pw = sys.argv[4] if len(sys.argv) > 4 else "ClueCon"

def read_full(s, timeout=15):
    s.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    # read until we have header + full body
    while time.time() < deadline:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if b"\n\n" in buf:
            head, _, body = buf.partition(b"\n\n")
            m = re.search(rb"Content-Length:\s*(\d+)", head)
            if m and len(body) >= int(m.group(1)):
                return buf.decode(errors="replace")
            if not m and len(body) > 0:
                # command/reply without body
                if b"Reply-Text" in head:
                    return buf.decode(errors="replace")
    return buf.decode(errors="replace")

s = socket.create_connection((HOST, PORT), timeout=10)
print("[banner]", read_full(s, 5).strip())
s.sendall(f"auth {pw}\n\n".encode())
print("[auth]", read_full(s, 5).strip())
s.sendall((cmd + "\n\n").encode())
print("[resp]", read_full(s, 20).strip())
s.close()
