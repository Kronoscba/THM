# Operation Slither — OSINT Investigation Report

**Room:** TryHackMe — Operation Slither  
**Date:** 2026-06-26  
**Investigator:** pi-coding-agent  
**Classification:** OSINT / Cyber Threat Intelligence

---

## Executive Summary

This report documents the findings of an OSINT investigation into a cybercriminal group operating under the monikers **v3n0mbyt3_**, **_myst1cv1x3n_**, and **sh4d0wF4NG**. The group was identified through a hacker forum post advertising stolen data and selling phishing infrastructure. Cross-platform reconnaissance, social media analysis, and developer platform enumeration revealed the group's operational structure, communication channels, and infrastructure.

---

## Activity 1 — First Operator: v3n0mbyt3_

**Initial Lead:** Hacker forum post by `@v3n0mbyt3_` advertising a 60 GB data breach of TryTelecomMe.

### Reconnaissance

- **Username:** `v3n0mbyt3_`
- **Identified platforms:** Chess, Discord, Scratch, TikTok, omg.lol, Threads
- **Active platform besides Twitter/X:** Threads
- **Threads profile:** Active account with 95 followers and 4 threads posted
- **Scratch profile:** Bio contained hints for other room questions

### Findings — Threads Conversation

A thread posted by `v3n0mbyt3_` contained a reply from a second user:

| User | Date | Message |
|------|------|---------|
| v3n0mbyt3_ | 21/04/2024 | lazy day 💤 |
| _myst1cv1x3n_ | 21/04/2024 | still recovering? 🤣 |
| v3n0mbyt3_ | 21/04/2024 | Yea for sure. That last OP was wild. |
| _myst1cv1x3n_ | 21/04/2024 | I still can't believe that they are still not aware of us for weeks. |
| v3n0mbyt3_ | 21/04/2024 | 🤣 time to harvest soon! |
| _myst1cv1x3n_ | 23/04/2024 | I really can't get over with this one 🤪 |

The last message from `_myst1cv1x3n_` contained a Base64-encoded string:

```
VEhNe3NsMXRoM3J5X3R3MzN0el80bmRfbDM0a3lfcjNwbDEzcyF9
```

**Decoded → `THM{sl1th3ry_tw33tz_4nd_l34ky_r3pl13s!}`**

### Questions Answered

| # | Question | Answer |
|---|----------|--------|
| 1 | Aside from Twitter / X, what other platform is used by v3n0mbyt3_? | `threads` |
| 2 | What is the value of the flag? | `THM{sl1th3ry_tw33tz_4nd_l34ky_r3pl13s!}` |

---

## Activity 2 — Second Operator: _myst1cv1x3n_

**Initial Lead:** Reply interaction with `v3n0mbyt3_` on Threads.

### Reconnaissance

- **Username:** `_myst1cv1x3n_`
- **Display name:** Mystic v1x3n
- **Bio:** "Delightfully Chaotic xo"
- **Identified platforms:** Threads (50 followers, 3 threads), TikTok, Chess.com, BoardGameGeek, omg.lol, **Instagram**

### Findings

Instagram account of `_myst1cv1x3n_` contained a comment with a Base64-encoded string:

```
VEhNe0hFTExPX0dVWVNfcG5kc2VjX3dhc19oZXJlfQ==
```

**Decoded → `THM{HELLO_GUYS_pndsec_was_here}`**

Additionally, the Scratch bio of `v3n0mbyt3_` contained a hint: *"The answer to question 5 is 'Pineapple$' btw"* — providing cross-references between room questions.

### Questions Answered

| # | Question | Answer |
|---|----------|--------|
| 1 | Username of the second operator | `_myst1cv1x3n_` |
| 2 | Value of the flag | `THM{HELLO_GUYS_pndsec_was_here}` |

---

## Activity 3 — Third Operator: sh4d0wF4NG

**Initial Lead:** Forum post advertising phishing infrastructure for sale.

> **FOR SALE** — Advanced automation scripts for phishing and initial access  
> Includes: Terraform scripts, Google Phishlet (evilginx v3.0), GoPhish automation,  
> Google MFA bypass, Cobalt Strike aggressor scripts, EDR bypass payloads  
> **Price:** $1500 | **Contact:** REDACTED@protonmail.com

### Reconnaissance

- **Username:** `sh4d0wF4NG`
- **GitHub profile:** `sh4d0wF4NG` — Bio: "Chillin" — 3 repositories
- **Email (from commits):** `sh4d0wF4NG@protonmail.com` ✅ matches the for-sale post
- **Other platforms:** Blogger, SoundCloud, TikTok, Xbox Gamertag

### GitHub Analysis

The `red-team-infra` repository contained exactly the infrastructure advertised:

| Component | Files |
|-----------|-------|
| **Terraform scripts** | `ec2_bastion.tf`, `ec2_evilginx.tf`, `ec2_gophish.tf`, `ec2_setup.tf`, `iam.tf`, `provider.tf` |
| **Python automation** | `gophish_parser.py` |
| **Fork — evilginx2** | Man-in-the-middle phishing framework |
| **Fork — gophish** | Open-Source Phishing Toolkit |

The `iam.tf` configuration reveals an IAM user with **AdministratorAccess** policy — a significant OPSEC failure, exposing the operator's AWS infrastructure.

### Flag Discovery

A commit in the `red-team-infra` repository contained a Base64-encoded string embedded in the commit data:

```
VEhNe3NoNHJwX2Y0bmd6X2wzNGszZF9ibDAwZHlfcHd9
```

**Decoded → `THM{sh4rp_f4ngz_l34k3d_bl00dy_pw}`**

The flag translates to *"sharp fangs leaked bloody password"* — referencing the operator's name (`sh4d0wF4NG` → "shadow fang") and their OPSEC failure in leaking credentials via commits.

### Questions Answered

| # | Question | Answer |
|---|----------|--------|
| 1 | Handle of the third operator | `sh4d0wF4NG` |
| 2 | Other platform used by third operator | `github` |
| 3 | Value of the flag | `THM{sh4rp_f4ngz_l34k3d_bl00dy_pw}` |

---

## Operational Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                      Cybercriminal Group                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Operator 1              Operator 2              Operator 3     │
│   v3n0mbyt3_              _myst1cv1x3n_           sh4d0wF4NG    │
│   ├── Twitter/X           ├── Threads             ├── GitHub     │
│   ├── Threads             ├── Instagram           ├── Blogger    │
│   ├── Scratch             ├── TikTok              ├── SoundCloud │
│   └── Chess (dead)        ├── Chess               ├── TikTok     │
│                           ├── BoardGameGeek       └── Xbox       │
│                           └── omg.lol                              │
│                                                                  │
│   Communication: Threads (between Op1 ↔ Op2)                    │
│   Sales channel: Hacker Forum + ProtonMail                      │
│   Infrastructure: AWS (Terraform + evilginx2 + GoPhish)         │
│   Likely group: PnDsec (mentioned in Activity 2 flag)           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Indicators of Compromise (IOCs)

### Usernames
| Username | Role |
|----------|------|
| `v3n0mbyt3_` | First operator / initial access |
| `_myst1cv1x3n_` | Second operator / communications |
| `sh4d0wF4NG` | Third operator / infrastructure developer |

### Contact
| Type | Value |
|------|-------|
| ProtonMail | `sh4d0wF4NG@protonmail.com` |

### GitHub
| URL | Description |
|-----|-------------|
| `https://github.com/sh4d0wF4NG` | Operator 3 profile |
| `https://github.com/sh4d0wF4NG/red-team-infra` | Phishing infrastructure (Terraform) |
| `https://github.com/sh4d0wF4NG/evilginx2` | Fork of evilginx2 framework |
| `https://github.com/sh4d0wF4NG/gophish` | Fork of GoPhish toolkit |

### Social Media
| Platform | Profile |
|----------|---------|
| Threads | `@v3n0mbyt3_` / `@_myst1cv1x3n_` |
| Instagram | `@_myst1cv1x3n_` |
| Scratch | `@v3n0mbyt3_` |
| TikTok | `@v3n0mbyt3_` / `@sh4d0wF4NG` |

---

## OPSEC Observations

1. **Cross-platform username reuse** — All three operators used the same or similar handles across multiple platforms, making correlation trivial.
2. **ProtonMail exposure** — `sh4d0wF4NG` committed code using their ProtonMail address, directly linking their GitHub identity to the for-sale post.
3. **IAM misconfiguration** — The Terraform scripts grant `AdministratorAccess` to the IAM user, representing significant operational security failure.
4. **Base64 in commits** — The flag was found embedded as a Base64 string in repository commit data, indicating poor operational security and data leakage.

---

## Recommendations

- Monitor the identified ProtonMail address and GitHub accounts for future activity.
- Track the `red-team-infra` repository for new infrastructure templates.
- Correlate AWS infrastructure deployment patterns using the identified region (`ap-southeast-2`) and naming conventions.
- Add all usernames to threat intelligence platforms for cross-correlation.

---

*Report generated by pi-coding-agent — 2026-06-26*
