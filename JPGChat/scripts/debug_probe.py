import socket, time
s = socket.create_connection(("10.64.159.126",3000), timeout=10)
s.settimeout(2)
def rd():
    try:
        return s.recv(4096)
    except Exception as e:
        return b"<<timeout>>"
time.sleep(0.5)
print("BANNER:", rd())
s.sendall(b"[REPORT]\n"); time.sleep(0.5)
print("AFTER [REPORT]:", rd())
s.sendall(b"testname\n"); time.sleep(0.5)
print("AFTER name:", rd())
s.sendall(b"testreport\n"); time.sleep(0.5)
print("AFTER report:", rd())
s.close()
