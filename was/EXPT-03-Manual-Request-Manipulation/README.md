# EXPT-03-Manual-Request-Manipulation.md

_(Copy this whole file into your repo as `EXPT-03-Manual-Request-Manipulation.md`. — **Note:** this file **does not** include Mutillidae install steps — it assumes Mutillidae is already installed and reachable at `http://localhost/mutillidae/`.)_

---

# Experiment 3 — Manual Request Manipulation (Kali + Mutillidae + Burp)

**Platform:** Kali Linux + Mutillidae + Burp Suite
**Purpose (one-liner):** learn how to capture, modify and replay HTTP requests to test application behavior and vulnerabilities using Burp Suite’s **Repeater** and **Intruder**, and how to document proof of testing for a lab exam.
**Important:** Only test targets you are authorized to test (Mutillidae / DVWA / lab VMs). Use conservative payloads and small lists in the exam to avoid accidental destructive actions. ([PortSwigger — Repeater & Intruder][1])

---

# Table of contents

1. Prerequisites (software + lab)
2. Quick checklist (one-page)
3. Step-by-step procedure — reproduce an action, send to Repeater, experiment, and document
4. Using Intruder safely (small fuzz/brute tests)
5. Tests & payload list (safe, exam-friendly)
6. Fallback: If Mutillidae doesn't work — use DVWA (how to use)
7. What to capture & sample evidence to show teacher
8. Mitigations / how to fix issues found
9. Short theory / notes to read aloud in the practical
10. Appendix: useful commands & tips
11. Minimal lab report template (copy-paste)

---

## 1) Prerequisites

- Kali Linux (updated).
- Mutillidae running at `http://localhost/mutillidae/` (or lab host).
- Burp Suite installed (Community or Professional). Repeater and Intruder are available in Community; Intruder has full features in Pro but basic usage is fine in Community.
- Firefox (or Burp’s embedded browser) configured to use Burp proxy; Burp CA certificate imported.
- Basic familiarity with HTTP (GET/POST/headers/cookies).
- Small wordlists/payload lists saved locally (you can create a `payloads/` folder).

---

## 2) Quick checklist (one-page before starting exam)

- [ ] Start Apache & MySQL (if required): `sudo systemctl start apache2` and `sudo systemctl start mariadb`.
- [ ] Open `http://localhost/mutillidae/` in proxied browser — verify page loads and requests are captured in Burp Proxy → HTTP history.
- [ ] Add host to Burp scope (Target → Scope).
- [ ] Identify a test action (login form, search, comment post, profile update) and perform it once to capture the request.
- [ ] Right-click the captured request → **Send to Repeater** → test modifications. Save screenshots.
- [ ] For small fuzzing tests (password list, param fuzz), **Send to Intruder**, use very small lists (5–20 items) and observe results.
- [ ] Save Burp project + evidence screenshots + `finding_summary.md`.

---

## 3) Step-by-step procedure (capture → Repeater → analyze)

> This example uses a login form and a search parameter, but the same flow applies to any HTTP request.

### A. Capture the request (Proxy → HTTP history)

1. Open Burp → **Proxy → Options** → ensure listener on `127.0.0.1:8080`.
2. Configure browser proxy to `127.0.0.1:8080` and import Burp CA cert.
3. In browser, go to `http://localhost/mutillidae/` and perform the action you will test (e.g., attempt login with `username=any` & `password=abc`).
4. In Burp → **Proxy → HTTP history**, find the request entry for the POST (or GET) you just made. Right-click it and **Show request** to confirm it’s the right one.

### B. Send to Repeater (safe, controlled experimentation)

1. Right-click the request in HTTP history → **Send to Repeater**.
2. Switch to **Repeater** tab → select the request. You will see the full raw HTTP request on the left and the response on the right after you click **Go**.
3. **Modify parameters** (examples below) — change `password=abc` to `password=admin` or inject test strings like `<script>alert(1)</script>`.
4. Click **Go** after each change and observe: response status, response length, headers, and body content. Note differences (redirects, 200 vs 500, different content, cookie changes).
5. For each behavior change, take a screenshot and save the exact raw request/response (in Repeater you can right-click → Save item).

**Why use Repeater?** Repeater is perfect for precise, iterative manipulation of a single request to learn how the server reacts to small changes.

---

## 4) Using Intruder safely (small fuzz / controlled brute)

> Intruder can automate tests across many payloads. In exam, **limit to very small lists** (5–20 entries) to be ethical and to finish fast.

### A. Prepare a small payload list

Create `payloads/passwords.txt`:

```
admin
password
123456
letmein
test123
```

### B. Send to Intruder & set positions

1. Right-click a captured login POST request → **Send to Intruder**.
2. In **Intruder → Positions**, click **Clear §** then highlight the parameter value you want to test (e.g., `password=abc`) and click **Add §**. Only mark the parameter(s) you intend to fuzz.
3. In **Payloads → Payload set 1**, load file `payloads/passwords.txt`.
4. **Start attack**. (Community edition runs locally and may be slower; Pro is faster.)
5. Watch results: sort by **Length** or **Status** to spot anomalies (e.g., a success may return `302` redirect or a different length).
6. **Stop immediately** if you detect account lockout, or anything unexpected.

**Important safety notes:**

- Use tiny lists in exam to avoid lockouts and noisy behavior.
- Document that you limited the attack and why.

---

## 5) Tests & payload list (safe, exam-friendly)

Use these small payloads to test common behaviors. Always explain the test intent in your report.

**XSS quick tests (for reflected contexts)**

- `<script>alert(1)</script>`
- `"><img src=x onerror=alert(1)>`
- `%3Cscript%3Ealert(1)%3C/script%3E` (URL-encoded)

**SQLi quick tests (non-destructive)**

- `' OR '1'='1`
- `1' -- `
- `1' OR '1'='1' -- `

**Authentication fuzz (password list — tiny)**

- `admin`, `password`, `123456`, `letmein`, `changeme`

**Directory traversal quick tests**

- `../../../../etc/passwd`
- `..%2F..%2F..%2Fetc%2Fpasswd` (URL-encoded)

**Header tampering**

- Modify `Cookie: session=...` values (only in local lab).
- Modify `User-Agent` or `Referer` in Repeater and observe behavior.

---

## 6) Fallback: If Mutillidae doesn't work — use DVWA (how to use)

If Mutillidae is unreachable, DVWA has equivalent pages for learning request manipulation.

1. Start services: `sudo systemctl start apache2` & `sudo systemctl start mariadb`.
2. Open `http://localhost/dvwa/` via proxied browser.
3. Login (DVWA default creds, or set them) and set “Security” to **low** for testing.
4. Use DVWA modules: **Brute Force**, **SQL Injection**, **XSS**, **Command Injection** to replicate the same Repeater/Intruder workflows.

---

## 7) What to capture & sample evidence filenames (put these in `evidence/`)

1. `evidence/01_mutillidae_action_capture.png` — screenshot of the action in the browser (e.g., login form) with Burp Proxy visible.
2. `evidence/02_burp_http_history.png` — HTTP history entry for the captured request.
3. `evidence/03_repeater_before_after.png` — Repeater showing the original request and a modified request with response.
4. `evidence/04_intruder_summary.png` — Intruder results table (small payload run) sorted by length/status.
5. `evidence/05_repeater_raw_save.txt` — saved raw HTTP request/response from Repeater (right-click → Save item).
6. `commands.txt` — terminal commands used (`curl -I`, `nmap` if run).
7. `finding_summary.md` — short one-page summary with the top finding & remediation.

**How to save requests**: In Burp Repeater/Proxy → right-click request → **Save item**. Save as `.txt` for append to evidence zip.

---

## 8) Mitigations / remediation notes (what to say in report)

When you present findings, pair each with a concrete remediation:

- **Broken authentication / weak creds:** enforce strong password policy, account lockouts after limited failed attempts, multi-factor authentication.
- **XSS:** output-encode based on context (HTML/JS/attribute), use Content Security Policy (CSP), sanitize user input on output.
- **SQL injection evidence:** use parameterized queries / prepared statements and avoid concatenating user input into SQL.
- **Directory traversal / LFI:** validate and canonicalize file paths, use an allow-list of permitted pages, and avoid direct filesystem includes from user input.
- **Header/cookie tampering:** mark cookies `HttpOnly` + `Secure` + `SameSite`; validate any auth tokens server-side.

---

## 9) Short theory / explanation (2–3 sentences to tell the teacher)

**Repeater** is an interactive tool for sending a single HTTP request repeatedly with manual modifications to observe server behavior. **Intruder** automates sending many payloads across chosen positions (parameters) to find anomalies such as authentication bypass or input validation failures. Use Repeater for precise confirmation and Intruder for small controlled fuzzing; always test only authorized targets.

---

## 10) Appendix — useful commands & quick tips

```bash
# Start services
sudo systemctl start apache2
sudo systemctl start mariadb

# Quick check of URL (see headers)
curl -I http://localhost/mutillidae/

# Small nmap (optional)
nmap -sV -T4 -oN evidence/06_nmap.txt 127.0.0.1

# Create tiny password list
mkdir -p payloads
echo -e "admin\npassword\n123456\nletmein\ntest123" > payloads/passwords.txt

# Screenshot selective area (Kali)
gnome-screenshot -a -f ~/Desktop/evidence/03_repeater_before_after.png
```

**Exam tips**

- Keep all payload lists tiny — show you know how to use the tool without launching noisy attacks.
- Always add the host to Burp scope before testing.
- Save a single clean example of a before/after request in Repeater as your canonical PoC.
- If an instructor asks for re-run: re-open Repeater, load saved raw request, reproduce in 30–60s.

---

## 11) Minimal lab report template (copy-paste into `finding_summary.md`)

```
# Finding Summary — EXPT-03 Manual Request Manipulation
**Student:** <Your Name>
**Date:** <dd-mm-yyyy>
**Target:** http://localhost/mutillidae/
**Tools:** Kali Linux, Burp Suite (Community/Pro)

## 1) Steps performed
1. Captured login/search request in Burp Proxy → HTTP history.
2. Sent request to Repeater and performed iterative parameter modifications.
3. Performed a small Intruder run against the password parameter using a 5-entry list.
4. Saved evidence: Repeater raw request/response and Intruder results screenshot.

## 2) Key finding (example)
- **Issue:** Authentication bypass behaviour observed with a special payload (example).
  **PoC:** Repeater request changed from `password=abc` to `password=admin` produced a 302 redirect to dashboard. Evidence file: `evidence/03_repeater_before_after.png`.
  **Remediation:** Implement account lockout, enforce strong password policy, use rate limiting and server-side credential validation.

## 3) Commands run
- `curl -I http://localhost/mutillidae/`
- `nmap -sV -T4 127.0.0.1 -oN evidence/06_nmap.txt` (optional)

## 4) Conclusion
Used Burp Repeater for controlled request manipulation and Intruder for small-scale automated testing. Findings show how parameter tampering and weak authentication can be quickly verified; recommend immediate hardening of authentication controls and input validation.

```

---

# Citations & references

- PortSwigger — Repeater docs & guide. ([PortSwigger — Repeater][1])
- PortSwigger — Intruder usage & guidance. ([PortSwigger — Intruder][1])
- OWASP Mutillidae II project page. ([OWASP Mutillidae II][2])
- DVWA (fallback) — Kali Tools page. ([Kali Linux — DVWA][3])

---
