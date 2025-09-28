Experiment 2 — Crawling & Scanning a Web App

Platform: Kali Linux + Mutillidae + Burp Suite
Purpose: discover the web app surface (pages/parameters) and scan/inspect for common vulnerabilities using Burp (Pro automated scanning if available; otherwise manual verification using Proxy / Repeater / Intruder).
Scope reminder: Only test systems you are authorized to test (Mutillidae / lab VMs / teacher-provided hosts).

Contents

Prerequisites

Quick checklist (one-page)

Step-by-step procedure (start → crawl → scan → analyze)

Manual verification tests to run (Community edition)

Fallback: If Mutillidae is not reachable — quick DVWA fallback (how to use)

What to capture & sample evidence files to show teacher

Mitigations / remediation notes (what to say in report)

Short explanation you can read aloud in the practical

Useful commands & quick tips

Minimal lab report template (copy-paste)

1. Prerequisites

Kali Linux up-to-date and running.

Mutillidae already installed and reachable at http://localhost/mutillidae/ (or lab host).

Burp Suite installed (Community or Professional). If you have Burp Pro you can run automated scans. Community = manual workflow.

Firefox (or Burp embedded browser) and Burp CA certificate imported for HTTPS.

Apache / MySQL running on Kali (if your Mutillidae uses local services).

Basic terminal familiarity for running small commands and taking screenshots.

2. Quick checklist (one-page before starting the exam)

Start Apache & MySQL: sudo systemctl start apache2 and sudo systemctl start mariadb (or mysql).

Open http://localhost/mutillidae/ in browser — verify page loads.

Launch Burp → Proxy listener 127.0.0.1:8080.

Configure browser proxy to 127.0.0.1:8080 and import Burp CA cert.

Browse Mutillidae while Burp Proxy captures requests → verify HTTP history populated.

Add host to Burp scope (Target → Scope).

Crawl (Pro) or manually browse all pages (Community).

Run scan (Pro) or perform manual checks (Repeater/Intruder).

Save Burp project + screenshots + finding_summary.md.

3. Step-by-step procedure (assumes Mutillidae is installed)
   A. Start services & verify target
   sudo systemctl start apache2
   sudo systemctl start mariadb # if Mutillidae uses DB

# verify

curl -I http://localhost/mutillidae/ # should return HTTP 200 headers

Open http://localhost/mutillidae/ in your browser (proxied) — you should see the Mutillidae homepage.

B. Burp setup (Proxy + browser)

Open Burp → Proxy → Options. Confirm an HTTP listener on 127.0.0.1:8080.

In Firefox: Preferences → Network Settings → Manual proxy 127.0.0.1 port 8080 (HTTP & HTTPS).

In Burp: Proxy → CA Certificate → export and import certificate into Firefox (so HTTPS pages load).

In Burp: Proxy → Intercept → Intercept Off (so browsing flows).

In Burp: Target → Scope → Add http://localhost/mutillidae (right-click host in Site map → Add to scope).

C. Crawl / Discover the site

Burp Pro (auto): Target → right-click host → Crawl & Audit (or use Spider/Crawler). Let it run until it finishes.

Burp Community (manual crawl): Use the browser to click every menu, link, form and follow the application flow (login pages, search, product pages, comment forms). Burp will populate Target → Site map automatically as you browse.

Keep a note (or screenshot) of how many unique paths/pages were discovered (Target → Site map shows this).

D. Save initial evidence

In Burp Proxy → HTTP history → right-click → Save selected items (save a few representative requests).

Take screenshots:

Mutillidae home page (browser with Burp visible)

Burp Site map (after crawling)

Example HTTP request in Proxy history

E. Scanning & initial analysis
If you have Burp Professional

In Target → Site map, right-click host or a directory → Scan → pick default profile → Start.

Let scanner run until it finishes (time varies).

Export scan results: Scanner → Reports → save HTML/PDF.

For each finding, open it and Save screenshot showing evidence and suggested remediation.

If you have Burp Community (manual)

Use Proxy history to find interesting endpoints (login, search, comment, upload).

For each endpoint:

Right-click → Send to Repeater → craft test payloads and click Go to observe responses.

Right-click → Send to Intruder (for small, safe fuzzing lists; be conservative in exams).

Look for anomalies: different response lengths/status codes, error messages, stack traces, sensitive data in responses.

4. Manual verification tests (high-value checks to run quickly)

Each test: show the original request, the modified request, response evidence, screenshot.

Parameter fuzz / simple injection test (in Repeater)

Inject <'script'>alert(1)</script> or 1' OR '1'='1 in parameters to test for XSS/SQLi. Observe the response.

Directory traversal test

Try ?page=../../../../etc/passwd (or URL-encode). Look for file contents.

Authentication check

Capture login POST. Try simple password variations (small wordlist) via Intruder — stop after a few attempts to avoid lockouts.

File upload / content type check

Upload a harmless text file and observe server behavior (filename, mime checks).

Header analysis

curl -I http://localhost/mutillidae/ — check server headers (server/version leakage, X-Frame-Options, Content-Security-Policy, Set-Cookie flags).

5. Fallback: If Mutillidae doesn't work — DVWA quick usage (no deep install steps required)

If Mutillidae is unreachable, use DVWA (Deliberately Vulnerable Web App) which is commonly present or easy to get on Kali.

Quick run (if DVWA already present on system)

Start services: sudo systemctl start apache2 and sudo systemctl start mariadb.

Open http://localhost/dvwa/ in proxied browser.

Login (use default DVWA credentials if preconfigured), set security level to low for exam tasks.

Perform the same crawling and manual tests described above (DVWA has pages for SQLi/XSS/CSRF etc.).

(If DVWA is not installed and you have time, you can install via package or use a prebuilt VM — but that is outside this file; your Mutillidae install doc already covers installation workflows.)

6. What to capture & sample evidence filenames (put these in evidence/ folder)

evidence/01_mutillidae_home.png — browser showing Mutillidae home (Burp visible).

evidence/02_burp_sitemap.png — Burp Target → Site map after crawl.

evidence/03_burp_http_history.png — Proxy HTTP history showing a sample request.

evidence/04_repeater_test.png — Repeater request + response after test payload.

evidence/05_scan_result.png — Burp scan finding (Pro) or manual finding screenshot.

evidence/06_nmap.txt — (Optional) quick nmap output: nmap -sV -T4 127.0.0.1 > evidence/06_nmap.txt

commands.txt — list of terminal commands you ran (start services, curl, nmap).

finding_summary.md — one-page summary (see template below).

How to take screenshots: Use gnome-screenshot -a -f ~/Desktop/filename.png or press PrintScreen and crop. Save with descriptive filenames.

7. Mitigations / Remediation (short, exam-ready points)

When writing recommendations or speaking to the teacher, use this concise list:

Input validation & output encoding — sanitize inputs and encode outputs to prevent XSS/SQLi.

Use parameterized queries / prepared statements — prevents SQL injection.

Harden cookies — HttpOnly, Secure, SameSite flags for session cookies.

Least privilege — application DB user should have minimal permissions.

Disable verbose error messages — avoid exposing stack traces or server versions.

Content Security Policy (CSP) — helps mitigate XSS.

WAF / Runtime protection — add a WAF for additional filtering on public apps.

Patch & update server components — ensure server, PHP, frameworks are up to date.

Include one specific remediation per finding in your report (e.g., “Use bind_param() for PHP mysqli prepared statements to fix SQLi on /product?id=”).

8. Short explanation (2–3 lines to tell the teacher)

Crawling discovers an application's pages, parameters and inputs (attack surface). Scanning tests those endpoints for weaknesses (XSS, SQLi, file inclusion). Automated scanners speed up detection but always verify results manually (Repeater/Intruder) to avoid false positives. All tests performed on authorized lab target.

9. Useful commands & quick tips (copy-paste)

# start services

sudo systemctl start apache2
sudo systemctl start mariadb

# quick site check

curl -I http://localhost/mutillidae/

# quick nmap (optional)

nmap -sV -T4 -oN evidence/06_nmap.txt 127.0.0.1

# take screenshot (select area)

gnome-screenshot -a -f ~/Desktop/evidence/burp_sitemap.png

Tips

Always add the host to Burp scope to avoid capturing system noise.

If Burp shows a lot of unrelated domains, filter by host in Site map.

Community edition → be methodical: browse every menu item and save the Site map screenshot; manual verification is exam-friendly.

Keep payloads small and stop brute force attempts quickly; document that you limited the attack for ethics.
