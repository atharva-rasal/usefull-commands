# Experiment 2 — Crawling & Scanning a Web App (Kali + Mutillidae + Burp)

_(Markdown file ready to save in your GitHub repo — copy this whole file to `EXPT-02-Crawling-and-Scanning.md`)_

---

> **Purpose (one-liner):** learn how to crawl (discover pages) and scan (find web vulnerabilities) on a deliberately vulnerable target using Kali + Mutillidae + Burp Suite — and how to produce exam-friendly evidence if Mutillidae isn’t usable.
> **Important:** Always run these tests **only** on lab targets you are authorized to test (Mutillidae / DVWA / Juice Shop). Burp’s automated scanner is available only in the Professional edition — the Community edition requires more manual testing. ([PortSwigger][1])

---

# Table of contents

1. Prerequisites (software + lab)
2. Quick checklist (one-page)
3. Full step-by-step — Mutillidae on Kali
4. Burp setup & crawling (how to capture pages)
5. Scanning (Burp Pro) and manual checks (Community)
6. Fallback: If Mutillidae doesn't work — use DVWA (quick install)
7. What to capture & sample evidence to show teacher
8. Mitigations / how to fix issues found
9. Short theory / notes you can read aloud in exam
10. Appendix: useful commands & tips

---

# 1) Prerequisites (what must be ready on your Kali machine)

- Kali Linux (updated).
- Burp Suite (Community or Professional) installed. If you have Burp Pro, automated scanning is possible; Community edition does manual testing. ([PortSwigger][1])
- Mutillidae (deliberately vulnerable webapp) installed and running on local web server, OR an alternative lab app (DVWA / Juice Shop) if Mutillidae fails. Mutillidae is an OWASP project and can be installed from its repo or preinstalled in many security distros. ([OWASP Foundation][2])
- Browser (Firefox recommended) with proxy settings and ability to import Burp CA certificate.
- Basic tools (apache2 / php / mysql) available if installing Mutillidae manually.

---

# 2) Quick checklist (one-page before starting exam)

- [ ] Start Apache + MySQL on Kali: `sudo systemctl start apache2` and `sudo systemctl start mariadb` (or `mysql`).
- [ ] Put Mutillidae into web root or ensure it’s running at `http://localhost/mutillidae/`.
- [ ] Launch Burp → Proxy listener on `127.0.0.1:8080`.
- [ ] Configure browser proxy to `127.0.0.1:8080` and import Burp CA cert.
- [ ] Open Mutillidae home page in proxied browser → verify requests appear in Burp Proxy HTTP history.
- [ ] Add target domain to Burp scope → start crawling / manual browsing.
- [ ] Run a scan (if Pro) or select important endpoints and use Repeater/Intruder/Manual checks (Community).
- [ ] Save Burp project + screenshots + short finding notes.

---

# 3) Full step-by-step — Mutillidae on Kali (install + run)

> Short note: there are multiple ways to get Mutillidae running (preinstalled images, XAMPP, copy to `/var/www/html`, Docker). The commands below are the _stable general approach_ used on Kali/Ubuntu. If you already have a prebuilt lab VM with Mutillidae, skip to “Start services.”

### Option A — (recommended) clone Mutillidae into Apache webroot

```bash
# 1. move to web root
cd /var/www/html

# 2. clone the official repo (OWASP / webpwnized)
sudo git clone https://github.com/webpwnized/mutillidae.git

# 3. set permissions
sudo chown -R www-data:www-data mutillidae
sudo chmod -R 755 mutillidae

# 4. start web services
sudo systemctl start apache2
sudo systemctl start mariadb   # or mysql

# 5. open the setup page in browser:
#    http://localhost/mutillidae/   (or http://127.0.0.1/mutillidae/)
```

_(If Mutillidae needs DB setup, follow on-screen setup or check `/mutillidae/` docs).)_ ([GitHub][3])

### Option B — use XAMPP (if you prefer GUI or Windows-like flow)

1. Install XAMPP (if not present), extract mutillidae into XAMPP's `htdocs` then start Apache & MySQL via XAMPP control. (Common on tutorials). ([Packt][4])

### Start / verify

- Visit `http://localhost/mutillidae/` in your browser. You should see Mutillidae splash page (with links, lab menu).
- If you see DB connection errors, double-check MySQL (`sudo mysql_secure_installation`) and the Mutillidae setup page (there is often a `set-up-database.php` script). Common troubleshooting: missing PHP modules (`php-mbstring`, `php-xml`, `php-curl`) — install via apt if error. ([Stack Overflow][5])

---

# 4) Burp Suite — setup, crawling (spidering), and capturing evidence

### 4.1 Configure Burp proxy & browser

1. Open Burp → **Proxy → Options** → ensure a listener exists at `127.0.0.1:8080`.
2. In the browser, set manual proxy to `127.0.0.1:8080` for HTTP/HTTPS, OR open Burp's embedded browser.
3. Install Burp CA certificate in browser (Proxy → CA certificate → export/import) so HTTPS sites don't break.

### 4.2 Add target to scope

1. In Burp: **Target → Site map → Add to scope** (right-click the host or use Target → Scope).
2. Scope ensures you’re testing only the lab host — good for exam clarity and ethical reasons.

### 4.3 Crawl / Spider (discover pages)

- **If you have Burp Pro:** use the **Crawl** / **Scanner** features to automatically spider the host (Target → Crawl or in Site map right-click → Crawl). The Pro scanner will both crawl and actively scan for vulnerabilities. ([PortSwigger][1])
- **If you have Burp Community:** the dedicated Spider may not be present; instead:

  1. Use Burp’s **Proxy** + browse the entire app (click all links, follow menus) — each request will populate **Target → Site map** automatically.
  2. Use Burp **Intruder** or manual lists only after you discover endpoints. (Manual crawling + Repeater is common in community edition.) ([Reddit][6])

### 4.4 What to watch in Burp while crawling

- **Site map:** shows discovered URLs and parameters.
- **Proxy → HTTP history:** raw requests/responses captured.
- **Target → Discovery results** (Pro): crawling summary.

---

# 5) Scanning & manual analysis (what to do once you have pages)

### 5.1 If you have **Burp Professional** (automated scanning)

1. Right-click a host or path in **Target → Site map** → **Scan** (or use “Crawl & audit”). Start scan. ([PortSwigger][1])
2. Let it run (time varies). Export scanner results -> **Report** → save as HTML/PDF for submission.
3. For each finding, click the item → read evidence and suggested remediation. Save screenshot of the finding pane.

### 5.2 If you have **Burp Community** (manual checks)

1. Use **Proxy history** to pick interesting endpoints (login, forms, search, upload).
2. For each endpoint:

   - **Send to Repeater** → modify parameters and observe responses (useful for injection, directory traversal, XSS test strings).
   - **Send to Intruder** (if permitted) → small password list or payload list (be careful with brute force).

3. Document each test: request payload, response status, length, and why it indicates an issue.

### 5.3 Other manual scans to run quickly (in Kali terminal)

- Quick port scan (if teacher asks):

```bash
nmap -sV -T4 -oN nmap_site.txt <target-ip-or-host>
```

- Simple curl header grab:

```bash
curl -I http://localhost/mutillidae/
```

Include outputs in your evidence zip.

---

# 6) Fallback: If Mutillidae doesn’t work — use DVWA (quick install on Kali)

> DVWA is available as a Kali package and is a reliable fallback for web vulnerability labs. ([Kali Linux][7])

### Quick DVWA install (Kali)

```bash
# install (Kali package)
sudo apt update
sudo apt install dvwa

# start the helper (if package provides dvwa-start)
dvwa-start      # launches a browser to DVWA interface (if available)
# OR start apache & mysql:
sudo systemctl start apache2
sudo systemctl start mariadb
# go to http://localhost/dvwa/setup.php and follow instructions
```

- DVWA gives similar targets (XSS, SQLi, CSRF) and works fine with Burp.

**Alternative:** OWASP Juice Shop (modern JS-based) — used when you want a richer UI, but it may require Node.js setup. If time is short, use DVWA.

---

# 7) What to capture & example evidence to show teacher (save for exam report)

Create a folder `evidence/` in your repo and include:

1. `screenshot_mutillidae_home.png` — Mutillidae home page opened in proxied browser (show Burp in background).
2. `burp_sitemap.png` — Site map after crawling (highlight number of pages discovered).
3. `burp_http_history.png` — an example request/response captured in Proxy (show a request with parameters).
4. `burp_repeater_example.png` — Repeater request + response where you modified a parameter (short caption).
5. `burp_scan_result.png` (if Pro) — one scanner finding screenshot with evidence & remediation. ([PortSwigger][1])
6. `nmap_output.txt` — output of quick nmap scan (if you ran it).
7. `commands.txt` — list of commands you ran (apache start, git clone, dvwa-start, nmap, curl).
8. Short text file `finding_summary.md` with: target, date/time, quick findings (3 bullets), tools used.

**How to take screenshots quickly on Kali**

- `gnome-screenshot -a` (select area) or use Print Screen and crop. Save with descriptive names.
- Use Burp → right-click → Save item for raw HTTP requests (saves as file).

---

# 8) Mitigations — what to say to fix issues found (short, exam-ready)

When you present findings, recommend concise, prioritized fixes:

- **Input validation & output encoding:** sanitize all user inputs and encode outputs to prevent XSS/SQLi.
- **Use parameterized queries / prepared statements** for DB access to prevent SQL injection.
- **Authentication & session hardening:** secure cookies (`HttpOnly`, `Secure`, `SameSite`), use strong password policy and rate-limiting.
- **Least privilege:** DB and app accounts should have minimal privileges.
- **Disable directory listing and reduce error verbosity** (don’t expose stack traces / versions).
- **Run automated scans in CI/CD** with authenticated scanning (only in controlled, authorized environments).
- **WAF / Runtime protection** for high-risk endpoints as an additional layer.

---

# 9) Short theory / explanation (2–3 sentences you can say to teacher)

- **Crawling** is the process of discovering the web application’s surface (pages, parameters, links) so we can enumerate attack surface. **Scanning** attempts to find security issues in those discovered endpoints (e.g., XSS, SQLi, RCE). Automated scanners (Burp Pro) speed this up, but manual verification (Repeater/Intruder) is essential to confirm true positives. Always scan only authorized targets and document scope. ([PortSwigger][1])

---

# 10) Appendix — useful commands & tips (copy-paste in terminal)

```bash
# Start web services
sudo systemctl start apache2
sudo systemctl start mariadb

# Clone Mutillidae into webroot
cd /var/www/html
sudo git clone https://github.com/webpwnized/mutillidae.git
sudo chown -R www-data:www-data mutillidae
sudo chmod -R 755 mutillidae

# Quick nmap (service detection)
nmap -sV -T4 -oN nmap_site.txt 127.0.0.1

# Save Burp HTTP request (in Proxy -> HTTP history -> right click -> Save selected items)
# (No terminal command — do it in Burp UI)

# DVWA quick install on Kali (fallback)
sudo apt update
sudo apt install dvwa
dvwa-start   # if packaging provides it, otherwise go to /var/www/html/dvwa/setup.php

# Screenshot example (Kali)
gnome-screenshot -a -f ~/Desktop/burp_sitemap.png
```

---

# Quick print-ready checklist (put this on top of your lab sheet)

- Target: `http://localhost/mutillidae/` (or `http://localhost/dvwa/` fallback).
- Tools: Kali, Burp Suite (Community/Pro), Apache, MySQL.
- Steps performed: installed/started app → configured proxy → crawled site → captured HTTP history → ran automated scan (Pro) OR performed manual Repeater checks (Community) → saved screenshots & Burp project.
- Evidence: `burp_sitemap.png`, `burp_http_history.png`, `burp_repeater_example.png`, `nmap_output.txt`.

---

# Citations & references

- OWASP Mutillidae II project page (Mutillidae description). ([OWASP Foundation][2])
- Mutillidae GitHub (installation instructions / repo). ([GitHub][3])
- Burp Suite official docs — running your first scan (Burp Scanner available in Pro). ([PortSwigger][1])
- Burp Free vs Pro differences summary (scanner not in Community). ([E-SPIN Group][8])
- DVWA Kali Tools page — DVWA available via `apt` in Kali. ([Kali Linux][7])

---
