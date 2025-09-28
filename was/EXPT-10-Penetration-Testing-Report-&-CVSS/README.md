# EXPT-10-Penetration-Testing-Report-&-CVSS.md

_(Copy this whole file into your repo as `EXPT-10-Penetration-Testing-Report-&-CVSS.md`. — ready-to-use, exam-friendly penetration-test reporting guide, CVSS scoring walkthrough, templates, and a completed example.)_

---

# Experiment 10 — Generate a Penetration Testing Report (CVSS + Mitigations)

**Platform:** Kali Linux + findings from previous experiments (Burp, nmap, sqlmap outputs, screenshots)
**Purpose (one-liner):** take the raw findings from your practical tests and convert them into a professional, exam-ready penetration test report that includes CVSS v3.1 scoring, prioritized remediation, and all evidence the examiner expects. This file contains templates you can copy-paste and one fully worked CVSS example.

---

## Contents

1. Prerequisites (what you should have before writing the report)
2. Quick checklist (one-page to finish quickly during the exam)
3. Report structure (section-by-section with text you can copy)
4. How to compute a CVSS v3.1 Base score — step-by-step worksheet + worked example
5. Findings table template (copyable Markdown table)
6. Prioritization & remediation matrix (how to choose quick wins)
7. Evidence checklist & filenames (what to attach)
8. Short oral script to present to your teacher (1-minute elevator pitch)
9. Appendix: sample commands, export tips, and final notes
10. Ready-to-paste files: `finding_summary.md`, `full_report_outline.md`, and `cvss-worksheet.md` (below)

---

## 1) Prerequisites (before creating the report)

- All evidence saved in a single `evidence/` folder (screenshots, saved raw HTTP requests, tool outputs).
- Short findings notes from each experiment (one line per finding).
- If using CVSS: CVSS v3.1 metric knowledge (this doc includes a worksheet).
- A text editor (VSCode / nano) and ability to export report to PDF if required.

---

## 2) Quick checklist (one-page to finish fast in the exam)

- [ ] Create folder `report/` and subfolder `report/evidence/`. Move evidence files there.
- [ ] Fill `finding_summary.md` (one page) — examiner usually asks for this first.
- [ ] Populate the Findings table (one row per finding) with proof links to `evidence/*`.
- [ ] For each high/critical finding, include: PoC steps, exact commands, screenshot, remediation.
- [ ] Compute CVSS v3.1 Base score for the top 3 findings (use worksheet below).
- [ ] Add an Executive Summary (2–3 lines, non-technical).
- [ ] Save final `full_report.md` and export to PDF if needed. Bring both Markdown and PDF to viva.

---

## 3) Report structure — section-by-section (copy & paste)

Use this structure for `full_report.md` (recommended). Each section has short example phrasing.

### Cover / Header

```
Penetration Test Report
Target: <target URL or IP>
Date: <dd-mm-yyyy>
Tester: <Your name>
Scope: Mutillidae local lab (http://localhost/mutillidae/)
Tools: Burp Suite (Community/Pro), nmap, sqlmap, Nikto, gobuster
```

### 1. Executive summary (2–4 sentences — non-technical)

```
During the authorized practical engagement on <date>, we crawled and tested the target application for common web vulnerabilities. Several low-to-medium issues were identified (XSS, information disclosure) that could lead to user impact. No production data was harmed — all testing was performed in a lab VM. Immediate recommended actions are a small set of quick fixes followed by deeper remediation.
```

### 2. Scope & methodology

```
Scope: Only http://localhost/mutillidae/ (local lab). No external or third-party systems were tested.
Methodology: Reconnaissance (nmap, whatweb), Crawling (Burp), Active testing (Repeater, Intruder), Automated tools (sqlmap where applicable). Tests were non-destructive and limited in volume. Evidence folder attached.
```

### 3. Findings (summary table) — see template in section 5.

### 4. Detailed findings (one subsection per finding)

For each finding include:

- Title / ID (e.g., FIND-001 — Reflected XSS)
- Severity (CVSS v3.1 score + rating)
- Affected endpoint(s) (exact URL + parameter)
- PoC (step-by-step reproducible) — include exact request lines and payloads
- Evidence file(s) (filenames)
- Impact explanation (short)
- Recommendation (concrete fix)
- CVSS scoring breakdown (attach worksheet)

Example snippet (use as copy-paste inside a finding):

```
FIND-001 — Reflected Cross-Site Scripting (XSS)
Severity: CVSS v3.1 — 3.3 (Low)
Endpoint: /search.php?q=
PoC (short):
1. Open http://localhost/mutillidae/search.php?q=test in proxied browser.
2. Send request to Repeater and replace q with `<script>alert(1)</script>`.
3. Click Go; observe alert in response or payload reflected unencoded.

Evidence:
- evidence/01_reflected_request.txt
- evidence/02_reflected_response.png

Impact: Reflected XSS could allow an attacker to run script in victim's browser (cookie theft, UI redress), but requires user interaction (low exploitability).

Remediation:
- Output-encode the 'q' parameter before rendering in HTML context.
- Implement Content Security Policy to restrict inline script execution.

CVSS (worksheet): AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N → Base score 3.3 (Low). See cvss-worksheet.md.
```

### 5. Remediation roadmap & priorities

- Quick wins (0–2 days): set secure cookie flags, remove server version headers, fix trivial input encoding.
- Medium (1–2 weeks): parameterize DB queries, enforce CSP, rate limit login attempts.
- Long-term: threat modeling, secure SDLC, automated pipeline scanning.

### 6. Appendix

- Raw tool outputs (nmap, sqlmap logs), Burp project (if allowed), commands used (copy/paste), and CVSS calculation worksheets.

---

## 4) How to compute CVSS v3.1 Base Score — worksheet + worked example

Use this when you need to justify the severity numerically. Fill the metric letters, then the numeric mapping and compute the base score.

### CVSS v3.1 Base Metrics (short mapping)

- **Attack Vector (AV):** Network (N) = 0.85 | Adjacent (A)=0.62 | Local (L)=0.55 | Physical (P)=0.20
- **Attack Complexity (AC):** Low (L)=0.77 | High (H)=0.44
- **Privileges Required (PR):** depends on Scope

  - Scope Unchanged: None (N)=0.85 | Low (L)=0.62 | High (H)=0.27
  - Scope Changed: None (N)=0.85 | Low (L)=0.68 | High (H)=0.50

- **User Interaction (UI):** None (N)=0.85 | Required (R)=0.62
- **Scope (S):** Unchanged (U) or Changed (C) — affects formula
- **Confidentiality / Integrity / Availability impact (C,I,A):** High (H)=0.56 | Low (L)=0.22 | None (N)=0.00

### CVSS base formula (conceptual)

1. Compute **Impact** = `1 - (1-C)*(1-I)*(1-A)`
2. Compute **Exploitability** = `8.22 * AV * AC * PR * UI` (where PR uses scope-dependent mapping)
3. If Scope = Unchanged: `BaseScore = min(Impact + Exploitability, 10)`
   If Scope = Changed: `BaseScore = min(1.08 * (Impact + Exploitability), 10)`
4. Round up to 1 decimal place (CVSS uses "round up" rule).

> **Worked example** — Reflected XSS we use in the earlier findings:

- Metric selection and rationale:

  - AV = Network (N) — attacker can host link → 0.85
  - AC = Low (L) — no special conditions → 0.77
  - PR = None (N) — attacker needs no privileges → 0.85 (Scope Unchanged)
  - UI = Required (R) — victim must click the link → 0.62
  - Scope = Unchanged (U)
  - Confidentiality = Low (L) — could leak cookies/partial data → 0.22
  - Integrity = Low (L) — modify displayed page for the user → 0.22
  - Availability = None (N) → 0.00

**Calculate:**

- Impact = `1 - (1-0.22)*(1-0.22)*(1-0.00) = 1 - 0.78*0.78*1 = 1 - 0.6084 = 0.3916`
- Exploitability = `8.22 * 0.85 * 0.77 * 0.85 * 0.62 ≈ 2.8353`
- Scope = Unchanged → Base = `min(Impact + Exploitability, 10)` = `0.3916 + 2.8353 = 3.2269` → round up to 1 decimal → **3.3**

**CVSS vector string:**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` → **Base score 3.3 (Low)**

> Use this worksheet for each finding you want to prioritize numerically. Put the completed vector and the final rounded score in the finding header.

---

## 5) Findings table template (copyable Markdown)

Use this short table in your report to give a quick overview (one row per finding). Link evidence filenames in the Evidence column.

```
| ID | Vulnerability | Endpoint(s) / Param | CVSS (v3.1) | Severity | Evidence |
|----|---------------|---------------------|-------------:|----------|----------|
| FIND-001 | Reflected XSS | /search.php?q= | 3.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N) | Low | evidence/01_reflected_request.txt, evidence/02_reflected_response.png |
| FIND-002 | SQL Injection | /product.php?id= | 9.0 (example) | High | evidence/02_request_txt, evidence/03_sqlmap_output.txt |
| FIND-003 | LFI | /index.php?page= | 7.2 (example) | High | evidence/01_lfi_request.txt, evidence/02_lfi_passwd.png |
```

> Fill in the CVSS vector and computed score for each important finding. If you don't compute CVSS for every row, compute at least for the top 3.

---

## 6) Prioritization & remediation matrix (quick guide)

Use this to decide what to fix first:

- **Critical (CVSS ≥ 9.0)**: Fix immediately — public-facing RCE, SQLi exposing user data. Quick fix: disable vulnerable endpoints, WAF rules, temporary config changes.
- **High (7.0–8.9)**: Fix in short term (days). Implement fixes (parameterized queries, patch versions).
- **Medium (4.0–6.9)**: Plan in next sprint; mitigations & secure coding.
- **Low (<4.0)**: Triage & fix in normal maintenance; add to backlog or quick wins (headers, cookie flags).

**Quick-wins examples**

- Add `HttpOnly/Secure/SameSite` cookie flags.
- Remove server version headers.
- Add input/output encoding to templates.
- Enforce `Content-Security-Policy` with nonce/hash for scripts.

---

## 7) Evidence checklist & recommended filenames

Put all artifacts under `report/evidence/` and reference them in the report.

**Recommended evidence files:**

- `evidence/01_reflected_request.txt` — raw request saved from Burp (Repeater).
- `evidence/02_reflected_response.png` — screenshot of reflected payload or alert.
- `evidence/03_sqlmap_output.txt` — sqlmap stdout showing detection.
- `evidence/04_sqlmap_dbs.txt` — `--dbs` output (if run).
- `evidence/05_nmap_top100.txt` — nmap scan output.
- `evidence/06_burp_sitemap.png` — screenshot showing site map.
- `evidence/commands.txt` — exact commands used (copy/paste).
- `evidence/final_report.pdf` — exported PDF version of full report.

Include also a small `report/README.md` that lists the files and short notes.

---

## 8) Short oral script (1 minute) — what to say to your teacher

> “I performed an authorized lab engagement against `http://localhost/mutillidae/`. I crawled the application with Burp, validated a few findings manually, and used sqlmap/nmap where safe. The top issue I found was a reflected XSS (FIND-001) — CVSS 3.3 (Low) — which I can show as a saved Repeater request and screenshot. I’ve included concrete remediation steps (encode output, CSP), a prioritized remediation roadmap, and all evidence in `report/evidence/`. Would you like me to reproduce a PoC now or walk through the CVSS calculation?”

Keep it short; show `finding_summary.md` then open the high-severity detailed finding.

---

## 9) Appendix — sample commands, exports & final notes

**Commands (examples to include in `commands.txt`):**

```bash
# export nmap
nmap -sV --top-ports 100 -oN report/evidence/05_nmap_top100.txt 127.0.0.1

# save Burp HTTP request: right-click in Proxy/Repeater -> Save item -> save under report/evidence/

# run sqlmap on a saved request
sqlmap -r report/evidence/request.txt --dbs --batch --level=1 --risk=1 > report/evidence/03_sqlmap_output.txt

# take screenshots (select area)
gnome-screenshot -a -f report/evidence/02_reflected_response.png
```

**Exporting to PDF:** Many Markdown editors (VSCode + Markdown PDF extension) or `pandoc` can convert:

```bash
# install pandoc, then:
pandoc full_report.md -o full_report.pdf
```

**Final notes**

- Keep the report factual — document what you did, when, and why.
- Never include captured real user credentials without explicit permission — mask sensitive values in the report or describe them abstractly.
- When asked to re-run a PoC, use your saved raw request in Burp Repeater and reproduce quickly.

---

## 10) Ready-to-paste files

Below are three ready-to-create files you can copy into your repo immediately.

### `finding_summary.md` (one-page summary — paste as-is and edit)

```
# Finding Summary — Practical PenTest
**Student:** <Your Name>
**Date:** <dd-mm-yyyy>
**Target:** http://localhost/mutillidae/
**Scope:** Local lab only (Mutillidae)
**Tools:** Burp, nmap, sqlmap

## Top Findings (summary)
1. FIND-001 — Reflected XSS — /search.php?q= — CVSS v3.1: 3.3 (Low). PoC and screenshot saved: report/evidence/01_reflected_request.txt, report/evidence/02_reflected_response.png
2. FIND-002 — SQL Injection — /product.php?id= — CVSS v3.1: (computed) — evidence: report/evidence/02_request_txt, report/evidence/03_sqlmap_output.txt
3. FIND-003 — LFI — /index.php?page= — CVSS v3.1: (computed) — evidence: report/evidence/01_lfi_request.txt, report/evidence/02_lfi_passwd.png

## Quick Recommendations (top 3)
- Encode all output and implement CSP to mitigate XSS.
- Use parameterized queries and least-privileged DB accounts to mitigate SQLi.
- Implement allow-list includes and disable remote file inclusion (allow_url_include=Off) for LFI.

## Evidence folder
All supporting screenshots, raw requests and tool outputs are in `report/evidence/`.
```

### `full_report_outline.md` (skeleton to expand)

```
# Penetration Test Report — <Target>

## Cover
(see header fields)

## Executive Summary
(2-4 sentences)

## Scope & Methodology
(list)

## Findings Summary
(include the Findings table here)

## Detailed Findings
- FIND-001 — Reflected XSS
  (full detail with PoC, evidence list, CVSS calculation)
- FIND-002 — SQLi
  (full detail)
... continue for each finding

## Remediation Roadmap
(Quick wins / medium / long-term)

## Appendix
- commands.txt
- raw tool outputs (list)
- CVSS worksheets (include per-finding)
```

### `cvss-worksheet.md` (one-per-finding — copy into each finding)

```
# CVSS v3.1 Worksheet — <FIND-ID>

Metric mapping chosen:
- AV: <N/A/L/P> → <numeric>
- AC: <L/H> → <numeric>
- PR: <N/L/H> (note Scope) → <numeric>
- UI: <N/R> → <numeric>
- S: <U/C>
- C: <N/L/H> → <numeric>
- I: <N/L/H> → <numeric>
- A: <N/L/H> → <numeric>

Impact = 1 - (1-C)*(1-I)*(1-A) = <calc>
Exploitability = 8.22 * AV * AC * PR * UI = <calc>

Base Score (Scope <U/C>): = <calc> → round up to 1 decimal → **<score>**

Vector: CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...
```

---
