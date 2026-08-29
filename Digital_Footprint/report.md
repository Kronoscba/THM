# Digital Footprint — OSINT Investigation Report

**Room:** TryHackMe — Digital Footprint  
**Date:** 2026-06-26  
**Investigator:** gabi  
**Target:** ACME Jet Solutions (warc-acme.com/jef/)

---

## Executive Summary

OSINT investigation into ACME Jet Solutions, a company claiming 2025 founding on social media. Using publicly available information — image metadata, Internet Archive records, domain WHOIS, and social media footprint — the investigation confirmed the company operated as early as 2016, identified the location of a property linked to its early operations, geolocated a landmark tied to its international expansion, and extracted credentials of a system administrator from a leaked internal document.

**Flags obtained: 4/4**

---

## Methodology

| Phase | Actions |
|-------|---------|
| Intelligence Gathering | Image EXIF extraction, GPS geolocation, Wayback Machine / Internet Archive queries, WHOIS lookups, social media enumeration via Sherlock |
| Analysis | Coordinate decoding, timestamp parsing, WARC metadata correlation |
| Exploitation (OSINT) | Sherlock username search across platforms |

---

## Findings

### FIND-001 — Residential Property Geolocation

| Field | Value |
|-------|-------|
| **File** | `edited-house-1763031553617.jpg` |
| **GPS Coordinates** | 26°12'14.76" S, 28°2'50.28" E |
| **Decoded Location** | Johannesburg, South Africa |
| **EXIF Present** | GPS Latitude, GPS Longitude |
| **Flag** | `Johannesburg` |

**Analysis:** The image uploaded by an ACME Jet Solutions employee contained embedded GPS metadata. The coordinates point to Johannesburg, South Africa — confirming the rumour about the property linked to the company's early operations.

**Evidence:**
- GPS Latitude: 26 deg 12' 14.76"
- GPS Longitude: 28 deg 2' 50.28"
- File: `edited-house-1763031553617.jpg`

---

### FIND-002 — Website First Publication Date

| Field | Value |
|-------|-------|
| **Target** | warc-acme.com/jef/ |
| **Archive Identifier** | `warc-acme.com-jef` |
| **First File Date** | `20160210224602` |
| **Publication Date** | 2016 |
| **Collection** | archiveteam_earlywarcs |
| **Flag** | `20160210224602` |

**Analysis:** The domain warc-acme.com does not exist in public WHOIS. However, a WARC (Web ARChive) file was found on the Internet Archive under the identifier `warc-acme.com-jef`, containing a full backup of `acme.com/jef/` with 183,762 items. The `firstfiledate` metadata field is `20160210224602` (2016-02-10T22:46:02 UTC), confirming the site has existed since at least **February 10, 2016** — contradicting the company's claim of a 2025 founding.

**Evidence:**
- Metadata: `firstfiledate: 20160210224602`
- Metadata: `publicdate: 2016-02-13 00:40:30`
- WARC size: 9.5 GB across multiple archives
- URL: https://archive.org/details/warc-acme.com-jef

---

### FIND-003 — International Expansion Landmark

| Field | Value |
|-------|-------|
| **File** | `landmark-1763035881792.JPG` |
| **Camera** | Canon PowerShot SX160 IS |
| **Photo Date** | ~2017 (modified 2017-07-04 via Windows Live Photo Gallery) |
| **Landmark** | General Post Office |
| **Flag** | `THM{General Post Office}` |

**Analysis:** The image shows an iconic landmark with a building to its right that played a significant role in a country's fight for independence. The General Post Office (GPO) in Dublin, Ireland served as the headquarters of the 1916 Easter Rising, a pivotal event in the Irish War of Independence. Signs on the building's external wall confirm its identity. This aligns with ACME Jet Solutions' claimed "international expansion" beyond their South African origins.

**Evidence:**
- EXIF: `Date/Time Original: 1980:01:01 00:00:22` (camera clock reset)
- EXIF: `Modify Date: 2017:07:04 11:10:36`
- EXIF: `Software: Microsoft Windows Live Photo Gallery14.0.8051.1204`
- Camera: Canon PowerShot SX160 IS
- File: `landmark-1763035881792.JPG`

---

### FIND-004 — Leaked Internal Document & System Administrator

| Field | Value |
|-------|-------|
| **File** | `internal-docs-1769695301727.odt` |
| **Author** | Mark (From: Mark → To: Robin) |
| **Internal Username** | `markwilliams7243` |
| **Generator** | LibreOffice/25.8.4.2 |
| **Description** | "Just remember Robin, don't publish this externally!" |
| **Social Media Found** | TikTok, YouTube |
| **Flag** | `THM{Y0u_f0und_7h3_fin4l_fl4g!}` |

**Analysis:** An internal ODT document was leaked by an ACME Jet Solutions developer. The document metadata reveals the internal username `markwilliams7243` (full name: Mark Williams based on the username convention). Sherlock enumeration across 400+ platforms confirmed active accounts on TikTok and YouTube under this username, positively identifying Mark Williams as the individual responsible for maintaining ACME Jet Solutions' systems.

**Evidence:**
- ODT metadata: `<meta:user-defined meta:name="Internal username">markwilliams7243</meta:user-defined>`
- ODT content: "From: Mark / To: Robin"
- Sherlock results: TikTok (@markwilliams7243), YouTube (@markwilliams7243)
- File: `internal-docs-1769695301727.odt`

---

## Evidence Inventory

| File | Type | Finding |
|------|------|---------|
| `edited-house-1763031553617.jpg` | Image with GPS EXIF | FIND-001 — Johannesburg |
| `landmark-1763035881792.JPG` | Image with camera metadata | FIND-003 — General Post Office |
| `internal-docs-1769695301727.odt` | LibreOffice document with metadata | FIND-004 — markwilliams7243 |
| Internet Archive: warc-acme.com-jef | WARC archive (9.5 GB) | FIND-002 — First published 2016 |

---

## Flags Summary

| # | Question | Flag |
|---|----------|------|
| 1 | City where the photo was taken | `Johannesburg` |
| 2 | When was the website first published? | `20160210224602` |
| 3 | Name of the landmark building | `THM{General Post Office}` |
| 4 | Final flag (system administrator) | `THM{Y0u_f0und_7h3_fin4l_fl4g!}` |

---

## Lessons Learned

- **EXIF data leakage:** Both photos contained metadata (GPS coordinates, camera info, software used) that was not stripped before upload. This is the primary OSINT vector.
- **WARC archives as OSINT source:** Even when a domain is no longer registered, Internet Archive WARC collections may contain complete snapshots.
- **Document metadata:** ODT/DOCX files often contain author names, usernames, edit history, and descriptions that are not visible in the document body.
- **Username correlation:** Sherlock enables rapid cross-platform identity discovery from a single username.
