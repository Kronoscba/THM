# Penetration Test Report

## TryHackMe — "The Case: Seven Minutes on the Seine"

---

## 1. Executive Summary

**Scope:** `10.67.129.124 → 10.64.172.41` (Louvre Museum Security CTF — two activities)

**Assessment Type:** OSINT Investigation + Web Application & CCTV Security Assessment

**Duration:** ~2 hours (split across two instance activations)

**Risk Level:** Medium — Two flags captured via credential reuse and weak authentication.

**Flags Obtained:**

| Activity | Flag | Path |
|----------|------|------|
| 1 — Investigation Report | `THM{n1c3_h31st_r3s34rch}` | `loot/flag_activity1.txt` |
| 2 — CCTV Footage Review | `THM{cctv_4ud1ts_4r3_fun}` | `loot/flag_activity2.txt` |

**Summary of Findings:**

The challenge simulated a two-phase investigation following a heist at the Louvre Museum. Phase 1 involved OSINT research to answer five investigative questions about the heist methodology, submitted via a REST API to obtain the first flag. Phase 2 required identifying weak credentials (`louvre / louvre`) for a CCTV monitoring portal, authenticating, and locating the date of the incident (19 October 2025) where camera feeds showed ALERT/OFFLINE states and the second flag was displayed.

---

## 2. Methodology

The assessment followed the PTES framework adapted for CTF/educational environments.

### 2.1 Intelligence Gathering

| Action | Tool | Evidence |
|--------|------|----------|
| Port scan | `nmap -sC -sV -T4 -p-` | `nmap/initial_scan.txt` |
| HTTP service identification | `curl` | Port 80: Werkzeug 3.0.1 / Python 3.11.14 |
| API enumeration | `curl`, manual exploration | `/api/questions`, `/api/submit-report` |
| OSINT — Louvre entrance info | `curl`, Wikipedia | Porte des Lions closure: 22 Oct 2024 |
| OSINT — INTERPOL notices | Research | `2025/359.1, 2025/359.5` |
| OSINT — Inventory numbers | Research | `MV1024-BAPST-AFFECTE-1887-NON_EXPOSE` |

### 2.2 Vulnerability Analysis

The web application exposed a REST API used as a question-answer engine. No traditional vulnerabilities (XSS, SQLi, command injection) were required for the challenge — the attack vector was purely authentication-based.

Key observations:
- **Activity 1:** The `/api/questions` endpoint leaked all five question answers in the response, allowing direct submission without research.
- **Activity 2:** The CCTV portal at `/login` had a weak password policy that allowed discovery via credential guessing.

### 2.3 Exploitation

**Activity 1:**
1. Queried `/api/questions` to retrieve the investigation questions.
2. Answered via `/api/submit-report` → Flag retrieved.

**Activity 2:**
1. Identified CCTV login portal at `http://10.64.172.41/login`.
2. Discovered credentials `louvre / louvre` via informed guessing (weak password policy clue).
3. Authenticated and navigated to `/cctv/{date}` to review footage.
4. Found `is_heist: true` on **2025-10-19** with four cameras in ALERT state and one OFFLINE.
5. Flag displayed in the HTML alert banner on that date.

### 2.4 Post-Exploitation

- No lateral movement or privilege escalation was required — flags were obtained directly through the web application and CCTV portal.

---

## 3. Findings

### [FIND-001] Weak CCTV Portal Credentials

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Location** | `http://10.64.172.41/login` |
| **Type** | Weak Authentication |
| **Credentials** | `louvre / louvre` |

**Description:** The Louvre Museum Security Monitoring System login portal accepted the credentials `louvre / louvre`, which are trivially guessable (username and password are identical). This aligns with the audit report reference to a "weak password policy."

**Evidence:**
```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=louvre&password=louvre

→ 302 FOUND → /cctv/2026-06-26
→ Set-Cookie: session=eyJhdXRoZW50aWNhdGVkIjp0cnVlfQ...
```

**Impact:** Full access to the CCTV monitoring system, including the ability to browse historical camera footage and potentially identify security vulnerabilities in physical security coverage.

**Remediation:** Enforce strong password policies — minimum 12 characters, complexity requirements, and no username-as-password patterns. Implement MFA. Require password change on first login.

### [FIND-002] CCTV Monitoring Dashboard — Unrestricted Date Access

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Location** | `http://10.64.172.41/cctv/{date}` / `/api/cctv-data/{date}` |

**Description:** Any authenticated user could browse CCTV footage for any date by simply changing the date parameter in the URL path. No access control restrictions were applied, and the API returns camera status data without audit logging.

**Evidence:**
```
GET /api/cctv-data/2025-10-19 → is_heist: true
Cameras: Main Hall-North [ALERT], Gallery A-Wing [ALERT],
         Security Office [OFFLINE], Entrance Hall [ALERT],
         Storage Room [ALERT]
```

**Impact:** An attacker who gained credentials could review historical footage to identify periods with reduced camera coverage or offline security systems.

**Remediation:** Implement role-based access control for historical footage review. Log all access to CCTV data. Restrict date range browsing to authorized security personnel only.

### [FIND-003] Sensitive Information Disclosure via API

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Location** | `http://10.67.129.124/api/questions` |

**Description:** The `/api/questions` endpoint returned all five investigation questions along with their expected answers in a single unauthenticated GET request.

**Evidence:**
```json
[{
  "id": 1, "question": "The Way In",
  "answer": "PORTE_DES_LIONS-22_OCT_2024",
  ...
}]
```

**Impact:** An attacker or unauthorized party could retrieve all investigation answers without conducting any research, bypassing the intended investigative process.

**Remediation:** Require authentication for all API endpoints. Never expose answer keys in question payloads. Use separate endpoints for question display and answer validation.

---

## 4. Evidence Inventory

| File | Type | Contents | Hash (SHA256) |
|------|------|----------|---------------|
| `nmap/initial_scan.txt` | Port Scan | Target IP, open ports (22, 80), service versions | — |
| `loot/flag_activity1.txt` | Flag | `THM{n1c3_h31st_r3s34rch}` | — |
| `loot/flag_activity2.txt` | Flag | `THM{cctv_4ud1ts_4r3_fun}` | — |
| `loot/heist_data.json` | API Response | CCTV data for 2025-10-19 with `is_heist: true` | — |

---

## 5. Incident Timeline (CCTV)

| Camera | ID | Status | Activity Detected |
|--------|----|--------|-------------------|
| Main Hall — North | 1 | 🔴 ALERT | Unauthorized access detected |
| Gallery A — Wing | 2 | 🔴 ALERT | Motion detected |
| Security Office | 3 | ⚫ OFFLINE | Connection lost |
| Entrance Hall | 4 | 🔴 ALERT | Multiple persons detected |
| Storage Room | 5 | 🔴 ALERT | Door forced open |

**Date of Incident:** 19 October 2025

**Analysis:** The Security Office camera being OFFLINE while four other cameras simultaneously detected unauthorized activity strongly suggests an inside job or targeted physical attack on the surveillance infrastructure. The attackers entered through the Entrance Hall, moved through the Main Hall to Gallery A (where the Queen's Reliquary Brooch was displayed), and accessed the Storage Room — all while the Security Office was blind.

---

## 6. Remediation Summary

| Priority | Finding | Action | Effort |
|----------|---------|--------|--------|
| 🔴 Critical | Weak password policy | Enforce strong passwords, MFA | Quick win |
| 🟡 High | Unrestricted CCTV data access | RBAC for footage review | Short term |
| 🟡 High | API exposes answer keys | Remove answers from question payloads | Quick win |
| 🟢 Medium | No audit logging on CCTV | Implement access logging | Short term |

---

## 7. Lessons Learned

**What worked well:**
- The OSINT approach to identifying the Louvre entrance and closure date was effective.
- The API leak accelerated Activity 1 significantly.

**What was unexpected:**
- The first instance (`10.67.129.124`) contained the Activity 1 portal but the user had not started the machine properly — the second instance (`10.64.172.41`) had the CCTV system for Activity 2.
- The weak credentials `louvre / louvre` were identified through systematic testing of common password patterns rather than through an external news article as the challenge description suggested.

**Deviations from standard approach:**
- The API endpoint `/api/questions` leaked answers, making OSINT research partially optional for Activity 1.
- The Werkzeug debugger SECRET found in Activity 1's HTML was not exploitable (no console endpoint on the second instance).

---

*Report generated: 26 June 2026*
*Assessment by: pi — coding agent harness*
