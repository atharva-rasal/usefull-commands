# EXPT-04-Reconnaissance-and-Information-Gathering.md

_(Copy this whole file into your repo as `EXPT-04-Reconnaissance-and-Information-Gathering.md` — assumes Kali + Mutillidae (or DVWA) already installed and reachable at `http://localhost/...`.)_

---

# Experiment 4 — Reconnaissance / Information Gathering (Kali + Mutillidae + Burp)

**Platform:** Kali Linux + Mutillidae (or DVWA) + Burp Suite + standard network tools
**Purpose (one-liner):** collect passive and active information about a lab target (DNS, WHOIS, open ports, running services, web technology stack, discovered directories/pages) to build an attack surface map for further testing.
**Ethics / scope reminder:** only perform recon on authorized lab targets (Mutillidae / DVWA / teacher-provided VMs). Always document scope & time. Recon is the first phase of any pentest. ([practicalinfosec.com][1])

---

## Contents

1. Prerequisites (software + lab)
2. Quick checklist (one-page)
3. Passive recon steps (OSINT, WHOIS, DNS, web-indexed data)
4. Active recon steps (nmap, port & service detection, NSE scripts)
5. Web recon (whatweb/wappalyzer, dirb/gobuster, nikto, Burp passive capture)
6. Fallback / offline notes (if network disabled)
7. What to capture & sample evidence to show teacher
8. Mitigations / defensive notes (what admins should do)
9. Short theory / notes to read aloud in the practical
10. Appendix — commands & quick tips
11. Minimal lab report template (copy-paste)

---

## 1) Prerequisites

- Kali Linux (updated) with network access to the lab host.
- Target reachable (e.g., `http://localhost/mutillidae/` or a provided VM IP).
- Tools installed (standard on Kali): `whois`, `dig`/`nslookup`, `nmap`, `whatweb`, `gobuster` (or `dirb`), `nikto`, `curl`, browser proxied through Burp.
- Small workspace: `~/expt04/` to store outputs and screenshots.

---

## 2) Quick checklist (one-page before starting exam)

- [ ] Confirm target & scope in writing (host/IP, allowed tests).
- [ ] Start services and verify app loads in browser: `curl -I http://<target>` .
- [ ] Passive recon first: WHOIS, dig, search engine checks (only public info).
- [ ] Active recon second: nmap (limited ports & -sV), run only fast, non-intrusive scans.
- [ ] Web recon: whatweb → gobuster (small wordlist) → nikto (light).
- [ ] Save all outputs to `~/expt04/evidence/` and take screenshots.
- [ ] Prepare `finding_summary.md` with top results and remediation suggestions.

---

## 3) Passive recon (OSINT without touching target servers directly)

> Goal: gather publicly available info that doesn’t interact with the target host itself (useful when target is remote). For local lab targets, passive steps are quick demonstration tasks.

### A. WHOIS — domain registration info

_What it does:_ returns registrar, registration/expiry, name servers, contact info (may be privacy-protected). Useful to learn ownership/contact and related domains. ([GeeksforGeeks][2])

**Command (example)**

```bash
whois example.com > ~/expt04/evidence/whois_example.txt
```

**What to record:** registrar, creation/expiry dates, name servers, any contact emails.

### B. DNS lookups (dig / nslookup)

_What it does:_ reveals A/AAAA, MX, NS, TXT (SPF, DKIM), CNAME records, useful for email spoofing surface, subdomain discovery, and misconfigured records. ([phoenixNAP | Global IT Services][3])

**Useful commands**

```bash
dig +noall +answer example.com A > ~/expt04/evidence/dig_A.txt
dig example.com ANY +short > ~/expt04/evidence/dig_any.txt
dig +trace example.com > ~/expt04/evidence/dig_trace.txt
```

**What to record:** mail servers (MX), TXT entries (SPF/DKIM), authoritative name servers, any unusual records.

### C. Search & OSINT (public index)

_What it does:_ look for publicly indexed files, backups, exposed pages using `site:` Google dork or local search tools. Keep this passive — do not crawl aggressively. You can demonstrate with a `site:` query screenshot (if internet allowed). ([4Geeks][4])

**Example note:** `site:example.com filetype:pdf` — screenshot search result.

---

## 4) Active recon (safe, limited interaction)

> Active recon interacts with the target but keep scans small/fast and within scope. Document every command you run.

### A. Ping / basic reachability

```bash
ping -c 4 <target-ip-or-host>
curl -I http://<target>    # quick HTTP headers
```

### B. Nmap — port & service detection (non-intrusive)

_Nmap is the canonical tool for port/service discovery and can also run scripts for more detail._ ([Nmap][5])

**Quick safe scan (recommended for exams)**

```bash
# SYN scan of top ports with service detection, output to file
nmap -sS -sV --top-ports 100 -T4 -oN ~/expt04/evidence/nmap_top100.txt <target-ip>
```

**Full quick scan (if allowed)**

```bash
nmap -sS -sV -p- -T4 -oN ~/expt04/evidence/nmap_allports.txt <target-ip>
```

**NSE scripts (light)** — only run a few safe scripts:

```bash
nmap -sV --script=http-title,http-server-header -oN ~/expt04/evidence/nmap_http_info.txt <target-ip>
```

**What to record:** open ports, service names & versions, HTTP title, server header. Save `nmap` output and screenshot for evidence.

_(Nmap docs: port scanning, NSE usage)._ ([Nmap][6])

### C. Banner grabbing / service probing

```bash
curl -I http://<target> > ~/expt04/evidence/curl_headers.txt
# or use ncat
ncat <target-ip> 80
```

Record `Server` headers and any version info (avoid fingerprinting-sensitive hosts outside lab).

---

## 5) Web recon (discover technologies & hidden content)

### A. WhatWeb / Wappalyzer — tech fingerprint

```bash
whatweb http://<target> -v > ~/expt04/evidence/whatweb.txt
# or use browser Wappalyzer extension and screenshot
```

_WhatWeb identifies frameworks, CMS, JS libs, server types — helps prioritize tests._

### B. Directory brute force (Gobuster / Dirb) — small/fast lists only

_Important:_ use a small wordlist in exams to be quick and non-intrusive.

```bash
# example with gobuster using a tiny list
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -t 20 -o ~/expt04/evidence/gobuster_common.txt
```

**What to record:** discovered directories (admin, uploads, backups). Screenshot Gobuster output.

### C. Web vulns quick scan (Nikto) — light mode

```bash
nikto -h http://<target> -o ~/expt04/evidence/nikto_output.txt
```

_Nikto reports common misconfigurations — use only in lab._

### D. Passive capture with Burp

1. Configure proxy and open app in browser → Burp captures requests.
2. Look at **Target → Site map** and **Proxy → HTTP history** to list endpoints and parameters for later testing.
3. Save HTTP history sample and screenshot.

---

## 6) Fallback / offline notes (if no network or local-only lab)

- If target is only local and you cannot use internet lookups (WHOIS/DNS), rely on local commands: `nmap`, `curl`, `whatweb`, `gobuster` against `127.0.0.1` or VM IP.
- For evidence, capture `nmap` output, `curl -I` headers and Burp Site map screenshot.

---

## 7) What to capture & sample evidence files (put these in `~/expt04/evidence/`)

Create folder and collect the following:

1. `whois_target.txt` — `whois` output.
2. `dig_any.txt` — `dig example.com ANY` output (or relevant DNS records). ([phoenixNAP | Global IT Services][3])
3. `nmap_top100.txt` — nmap port/service detection output (top 100 ports). ([Nmap][5])
4. `whatweb.txt` — technology fingerprint.
5. `gobuster_common.txt` — discovered directories (use a small wordlist).
6. `curl_headers.txt` — HTTP headers grabbed with `curl -I`.
7. `burp_sitemap.png` — Burp Site map screenshot after passive capture.
8. `commands.txt` — list of commands you ran (copy the exact commands).
9. `finding_summary.md` — one-page summary (template below).

**How to screenshot:** `gnome-screenshot -a -f ~/expt04/evidence/burp_sitemap.png` or use Print Screen.

---

## 8) Mitigations / defensive notes (what to tell the admin)

When reporting recon results, include hardening steps:

- **Remove or restrict information in public WHOIS / DNS** where possible (use privacy protection for registrant contact).
- **Minimize exposed services** — close unused ports and services; run only necessary daemons.
- **Patch and update software** that nmap identifies (outdated versions).
- **Harden web server**: remove detailed server banners, disable directory listing, set secure headers.
- **Harden DNS / email:** enforce SPF/DKIM/DMARC to prevent spoofing.
- **Monitor & rate-limit suspicious scans:** use IDS/WAF to detect heavy scanning and brute force attempts.

---

## 9) Short theory / explanation (2–3 sentences to read aloud)

Reconnaissance is the preparatory phase where testers gather publicly available and directly observable information about a target to map its attack surface. Passive recon collects OSINT (WHOIS, DNS, indexed content) while active recon probes the target (nmap, gobuster, nikto) — both must be performed within authorization and documented carefully. ([practicalinfosec.com][1])

---

## 10) Appendix — commands & quick tips (copy-paste)

```bash
# workspace
mkdir -p ~/expt04/evidence
cd ~/expt04

# Passive: whois & dig
whois example.com > evidence/whois_example.txt
dig example.com ANY +noall +answer > evidence/dig_any.txt

# Reachability
ping -c 4 <target-ip>
curl -I http://<target> > evidence/curl_headers.txt

# Safe nmap (top 100 ports with service detection)
nmap -sS -sV --top-ports 100 -T4 -oN evidence/nmap_top100.txt <target-ip>

# Nmap light NSE for HTTP info
nmap -sV --script=http-title,http-server-header -oN evidence/nmap_http_info.txt <target-ip>

# WhatWeb
whatweb http://<target> -v > evidence/whatweb.txt

# Gobuster (small list)
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -t 20 -o evidence/gobuster_common.txt

# Nikto (light)
nikto -h http://<target> -o evidence/nikto_output.txt

# Take a screenshot of Burp site map (select area)
gnome-screenshot -a -f ~/expt04/evidence/burp_sitemap.png
```

**Quick tips**

- Always document scope and time before starting.
- Keep scans small and fast for exams (top-ports, small wordlists).
- Save raw command outputs — they’re your evidence.
- If asked to re-run, use saved commands and files to reproduce results quickly.

---

## 11) Minimal lab report template (`finding_summary.md`)

```
# Finding Summary — EXPT-04 Reconnaissance & Info-Gathering
**Student:** <Your Name>
**Date:** <dd-mm-yyyy>
**Target:** <host or IP>
**Scope:** Passive + Light Active Recon (WHOIS, DNS, nmap, gobuster, whatweb)
**Tools:** whois, dig, nmap, whatweb, gobuster, nikto, curl, Burp Suite

## Steps performed
1. WHOIS lookup and DNS queries (whois, dig). See `evidence/whois_example.txt` and `evidence/dig_any.txt`.
2. Reachability & headers (ping, curl -I). See `evidence/curl_headers.txt`.
3. Nmap top-ports scan for services (nmap -sS -sV --top-ports 100). See `evidence/nmap_top100.txt`.
4. Web tech fingerprint (whatweb) and directory discovery (gobuster small list). See `evidence/whatweb.txt`, `evidence/gobuster_common.txt`.
5. Passive capture with Burp — site map screenshot `evidence/burp_sitemap.png`.

## Key observations (top 3)
1. [Info] HTTP server header reveals `Server: Apache/2.4.XX` — patch/update recommended. Evidence: `evidence/curl_headers.txt`.
2. [Info] Open ports: 80 (http), 22 (ssh) — nmap output `evidence/nmap_top100.txt`.
3. [Info] Discovered directory `/uploads/backup/` via gobuster — may contain sensitive files. Evidence: `evidence/gobuster_common.txt`.

## Remediations (short)
- Patch & update identified service versions; remove server banners.
- Restrict/close unused ports and services.
- Protect sensitive directories and disable directory listing.

## Commands run (append)
- whois example.com
- dig example.com ANY
- nmap -sS -sV --top-ports 100 -T4 <target-ip>
- gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt

## Conclusion
Performed passive OSINT and light active recon within scope. Findings are informational and show simple hardening steps for the target. All outputs saved in the `evidence/` folder.
```

---

## Citations & references (for your report / teacher)

- Nmap official docs & reference — use for port scanning and NSE guidance. ([Nmap][5])
- dig examples & DNS troubleshooting — guides explain `dig` usage. ([phoenixNAP | Global IT Services][3])
- whois command usage & description. ([GeeksforGeeks][2])
- Reconnaissance overview (OSINT + active recon) — practical pentesting guides. ([practicalinfosec.com][1])

---
