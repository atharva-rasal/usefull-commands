# EXPT-05-Session-and-Authentication-Attacks.md

_(Copy this whole file into your repo as `EXPT-05-Session-and-Authentication-Attacks.md`. — **Note:** this file **does not** include Mutillidae install steps — it assumes Mutillidae is already installed and reachable at `http://localhost/mutillidae/`.)_

---

# Experiment 5 — Attacking Session & Authentication (Kali + Mutillidae + Burp)

**Platform:** Kali Linux + Mutillidae (or DVWA) + Burp Suite
**Purpose (one-liner):** demonstrate controlled attacks against authentication and session management (small password fuzz/brute attempts, session cookie manipulation, session fixation, simple hijack proof-of-concept) using Burp’s tools — and document safe mitigations and evidence for the exam.
**Important:** Only test against authorized lab targets (Mutillidae / DVWA / teacher VM). Limit brute-force/fuzzing to tiny lists (5–20 entries) to avoid lockouts and noisy behaviour.

---

## Contents

1. Prerequisites (software + lab)
2. Quick checklist (one-page)
3. Step-by-step procedure — brute force (Intruder) & manual cookie manipulation (Repeater / Intercept)
4. Session fixation & hijack proofs (safe, lab-only)
5. Tests & small payload lists (exam-friendly)
6. Fallback: If Mutillidae doesn't work — DVWA modules to use
7. What to capture & sample evidence to show teacher
8. Mitigations / recommended fixes (exact phrasing for viva)
9. Short theory / notes to read aloud in the practical
10. Appendix — commands & quick tips
11. Minimal lab report template (copy-paste)

---

## 1) Prerequisites

- Kali Linux (updated).
- Mutillidae running at `http://localhost/mutillidae/` (or lab host with authentication pages).
- Burp Suite (Community or Pro). Repeater, Intruder, Proxy/Intercept available in Community; Intruder Pro features are faster but not necessary.
- Firefox (or Burp embedded browser) configured to `127.0.0.1:8080` and Burp CA imported.
- Small payload files saved locally (create `payloads/` folder).
- Basic knowledge of HTTP headers, cookies, and login flows.

---

## 2) Quick checklist (one-page before starting exam)

- [ ] Start Apache & MySQL (if required): `sudo systemctl start apache2` and `sudo systemctl start mariadb`.
- [ ] Open `http://localhost/mutillidae/` in proxied browser — confirm login page loads and requests are captured.
- [ ] Add host to Burp scope (Target → Scope).
- [ ] Identify test account(s) provided by lab or create a throwaway test user. **Never attack real user accounts.**
- [ ] For brute/fuzz tests: prepare tiny lists (5–20 items).
- [ ] Capture a normal login request (Proxy → HTTP history) → Save raw request.
- [ ] Reproduce attack in Repeater/Intruder, capture evidence, and stop after limited attempts.
- [ ] Save Burp project + screenshots + `finding_summary.md`.

---

## 3) Step-by-step procedure

### A. Capture the login request

1. In Burp: Proxy → Options → ensure listener at `127.0.0.1:8080`.
2. Browser (proxied) → Navigate to Mutillidae login page and perform a login attempt (use a lab/test credential or a dummy account).
3. Burp → Proxy → HTTP history → find the POST to `/index.php` or the login endpoint. Right-click → **Show request** and verify it's the correct login request. Save it: right-click → **Save item** (or send to Repeater).

Save a copy as `evidence/01_login_request.txt`.

### B. Safe brute-force / small password list with Intruder

> **Ethics & safety:** Use only tiny lists. Explain in report that you intentionally limited attempts.

1. Right-click the captured login POST → **Send to Intruder**.
2. Intruder → **Positions**: click **Clear §** then highlight the password value and click **Add §** so only `password` is a fuzz position. Leave username static (or use a test user if allowed).
3. **Payloads → Payload set 1**: Load a small file like `payloads/passwords.txt` (example below).
4. Start attack. Watch results, sort by **Length** or **Status** to find anomalies (e.g., a `302` or unique length for successful login).
5. **Stop immediately** after you find a success or after a predefined small number of tries (e.g., 10). Document that you stopped to avoid lockout.

Example `payloads/passwords.txt` (tiny):

```
admin
password
123456
letmein
test123
```

Save Intruder output screenshot as `evidence/02_intruder_results.png`.

### C. Manual verification with Repeater

1. From HTTP history, right-click request → **Send to Repeater**.
2. In Repeater, modify the `password` field to the candidate value that looked promising from Intruder and click **Go**.
3. Observe response: 200 vs 302 redirect to dashboard; different response length; new `Set-Cookie` header indicating authenticated session.
4. Save the raw successful request/response as `evidence/03_repeater_success.txt` and screenshot `evidence/04_repeater_success.png`.

### D. Session cookie inspection & modification (cookie manipulation)

1. After successful login in browser, find the authenticated request in Burp HTTP history. Inspect response headers for `Set-Cookie`. Note cookie name (e.g., `PHPSESSID`, `mutillidae_session`). Save header screenshot `evidence/05_setcookie.png`.
2. **Cookie tampering (simple test):** in Burp Intercept, intercept a request sent by the logged-in browser (a request to a privileged page). In the intercepted request, edit the `Cookie:` header (e.g., change `isAdmin=0` → `isAdmin=1` if such flags exist) and forward. Observe whether privilege changes. Save screenshot `evidence/06_cookie_tamper.png`.

   - If cookie values are opaque session IDs, change them to a guess or to a cookie from another session (e.g., open a second browser/private session, login as another user, copy their cookie value, and replace in the intercepted request) — **lab-only** proof-of-concept of session fixation/guessing.

3. **Set-Cookie flags check:** use `curl -I` or Burp to show `Set-Cookie` flags. If `HttpOnly`, `Secure`, or `SameSite` missing, note this in findings (`evidence/07_cookie_flags.txt`).

**Important:** If the application invalidates manipulated cookies or requires server-side validation, document that as good behavior.

---

## 4) Session fixation & hijack proofs (safe, lab-only)

### A. Session Fixation test (concept)

1. Create a session ID you control (visit site in browser A, capture session cookie).
2. In an attacker-controlled page (local HTML file), craft a link or form that forces the victim's browser to use your session ID (this is conceptual — in lab you can simulate by setting cookie in second browser). For exam, demonstrate by setting cookie in a second browser or using Burp to set `Cookie:` header with a session value and then logging in — show that session ID persisted across login (session ID not regenerated after authentication).
3. If the session is not regenerated on login → session fixation vulnerability. Capture evidence: before & after login `Set-Cookie` and session id equality `evidence/08_session_fixation.txt`.

### B. Simple Hijack (two-browser) proof

1. Open two browsers (normal and private) proxied through Burp.
2. In Browser A, login as test user — capture its session cookie.
3. In Browser B, replace its `Cookie:` header with Browser A’s session value (use Burp Intercept or edit in DevTools extension). If Browser B now has access to Browser A’s session (privileges), this demonstrates session hijack (lab-only). Capture screenshot `evidence/09_session_hijack.png`.
4. If the server binds session to IP/UA or regenerates tokens, the hijack will fail — document it as a safe control.

**Note:** explain in report that these steps were done in a local lab and were limited in scope.

---

## 5) Tests & small payload lists (exam-friendly)

**Passwords (tiny):** `admin`, `password`, `123456`, `letmein`, `qwerty`
**Cookie/test strings:** try short predictable tokens only in lab — never attempt with real accounts.

**Headers to try in Repeater (non-destructive):**

- `User-Agent: Mozilla/5.0` (change to something else)
- `Referer: http://attacker.local` (test Referer checks)
- `Cookie: PHPSESSID=<other-session-id>` (lab-only)

---

## 6) Fallback: If Mutillidae doesn't work — DVWA modules to use

- DVWA has modules directly relevant to this experiment: **Brute Force** (within DVWA) and **Login Authentication**.
- Use DVWA **Brute Force** for small password list tests and DVWA **Session Management** module (if present) for session/token checks. Set DVWA security **low** for lab demonstration.

---

## 7) What to capture & sample evidence filenames (put these in `evidence/`)

1. `evidence/01_login_request.txt` — saved raw login request (before attack).
2. `evidence/02_intruder_results.png` — Intruder results table showing small run and candidate success.
3. `evidence/03_repeater_success.txt` & `evidence/04_repeater_success.png` — Repeater raw success request/response.
4. `evidence/05_setcookie.png` — screenshot showing Set-Cookie header after login (cookie name & flags).
5. `evidence/06_cookie_tamper.png` — intercepted request where `Cookie:` header was edited.
6. `evidence/07_cookie_flags.txt` — `curl -I` or saved header showing missing `HttpOnly`/`Secure`.
7. `evidence/08_session_fixation.txt` — before/after session id comparison demonstrating fixation (if present).
8. `evidence/09_session_hijack.png` — two-browser hijack proof (if successful).
9. `commands.txt` — all terminal commands used.
10. `finding_summary.md` — short one-page summary of results and remediation.

**How to save raw HTTP from Burp:** right-click request in Proxy / Repeater → **Save item** (saves raw request+response).

---

## 8) Mitigations / recommended fixes (phrasing for viva)

Use these exact bullet points when speaking to the teacher:

- **Regenerate session ID on privilege changes / login:** on successful authentication, issue a new session identifier and invalidate the old one.
- **Set cookie flags:** mark session cookies with `HttpOnly`, `Secure` and `SameSite` attributes to reduce theft via XSS and CSRF.
- **Short session lifetime & idle timeout:** reduce window for hijack by limiting session lifetime and applying inactivity timeout.
- **Bind session tokens appropriately:** consider additional checks (IP address or User-Agent fingerprinting) with caution — avoid false positives for legitimate users.
- **Enforce strong authentication:** rate-limit login attempts, use account lockout or progressive delays, and prefer MFA where possible.
- **Password storage & policies:** store hashed passwords with a slow adaptive function (bcrypt/Argon2), enforce password complexity and rotation policies.
- **Audit & logging:** log authentication events and monitor for suspicious access patterns and repeated failed logins.
- **Do not store sensitive data in client-side cookies:** keep session data server-side; use opaque session identifiers.

---

## 9) Short theory / explanation (2–3 sentences to read aloud)

Session management vulnerabilities arise when session identifiers or authentication controls can be predicted, fixed, stolen, or tampered with. Effective defenses include regenerating session IDs on login, setting secure cookie flags (`HttpOnly`, `Secure`, `SameSite`), implementing rate-limiting/account lockouts, and using strong password storage and MFA. Always test these in an authorized lab and document your limited test scope.

---

## 10) Appendix — commands & quick tips (copy-paste)

```bash
# Start services (if needed)
sudo systemctl start apache2
sudo systemctl start mariadb

# Quick header check to see Set-Cookie flags
curl -I http://localhost/mutillidae/ > evidence/07_cookie_flags.txt

# Small nmap if instructor requests services
nmap -sV -T4 -oN evidence/nmap_session.txt 127.0.0.1

# Create tiny password list (example)
mkdir -p payloads
echo -e "admin\npassword\n123456\nletmein\ntest123" > payloads/passwords.txt

# Screenshot example (Kali)
gnome-screenshot -a -f ~/expt05/evidence/02_intruder_results.png
```

**Exam tips**

- Always use a lab/test account — never attack real accounts.
- Keep Intruder lists very small in exams and immediately stop after a success or after a set count. Note this in your report.
- Save one clean Repeater before/after pair as canonical PoC.
- If an instructor asks to re-run, use the saved raw request in Repeater and reproduce in under a minute.

---

## 11) Minimal lab report template (copy-paste into `finding_summary.md`)

```
# Finding Summary — EXPT-05 Session & Authentication Attacks
**Student:** <Your Name>
**Date:** <dd-mm-yyyy>
**Target:** http://localhost/mutillidae/
**Tools:** Kali Linux, Burp Suite (Community/Pro)

## 1) Steps performed
1. Captured login POST in Burp Proxy.
2. Sent login request to Intruder and ran a small 5-entry password list (ethical, limited).
3. Confirmed candidate success in Repeater and saved raw request/response.
4. Inspected Set-Cookie headers and attempted cookie tampering via Burp Intercept.
5. Simulated session fixation / two-browser hijack in lab (documented before/after session ids).

## 2) Key findings
- [Medium] Weak authentication behavior: small list produced a candidate that triggered a different response (302 redirect). Evidence: `evidence/02_intruder_results.png`, `evidence/03_repeater_success.png`.
- [Medium] Missing secure cookie flags: session cookie lacked `HttpOnly` / `Secure` (lab check). Evidence: `evidence/07_cookie_flags.txt`.
- [High/Info] Session fixation possible: session id persisted through login (if observed). Evidence: `evidence/08_session_fixation.txt`.

## 3) Remediations (short)
- Regenerate session IDs at login and on privilege changes.
- Set `HttpOnly`, `Secure`, `SameSite` on session cookies.
- Implement rate-limiting and account lockout; encourage MFA.
- Use strong password storage (bcrypt/Argon2) and enforce password policies.

## 4) Commands run
- curl -I http://localhost/mutillidae/ > evidence/07_cookie_flags.txt
- nmap -sV -T4 -oN evidence/nmap_session.txt 127.0.0.1 (optional)

## 5) Conclusion
Performed controlled authentication and session tests in the lab. Findings demonstrate common weaknesses in session handling which can be mitigated by session regeneration, secure cookie flags, and authentication hardening. All evidence saved in the `evidence/` folder.
```

---
