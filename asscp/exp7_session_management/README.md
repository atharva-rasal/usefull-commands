# Experiment 7 — Secure Session Management

## Objective

Show how to create secure sessions for users, protect them from hijacking, and enforce logout/timeout policies.

---

## Why Sessions?

- HTTP is **stateless** → server doesn’t remember users between requests.
- Sessions allow tracking user state (e.g., logged in or not).
- Session IDs (tokens) are stored in cookies and sent with each request.

---

## Common Session Vulnerabilities

- **Session Hijacking:** Attacker steals session cookie.
- **Session Fixation:** Attacker sets a known session ID before login.
- **Insecure Storage:** Session IDs stored in localStorage/URL.
- **No Timeout:** Sessions never expire, even if user inactive.

---

## Secure Practices

1. **Strong Session IDs**

   - Generate unpredictable, random IDs (e.g., 128-bit).
   - Use cryptographically secure libraries (like Flask’s `secret_key`).

2. **Secure Cookies**

   - Set flags:
     - `HttpOnly` → prevents JavaScript access.
     - `Secure` → only sent over HTTPS.
     - `SameSite=Strict` → blocks CSRF attacks.

3. **Session Timeout**

   - Auto-expire after inactivity (e.g., 5–15 min).
   - Force re-login after long absolute timeouts.

4. **Logout Mechanism**

   - Provide `/logout` endpoint that clears session.

5. **Regenerate Session IDs**
   - On login or privilege change → issue a fresh session ID.

---

## Python Flask Demo (Simple)

- `session["user"] = "student123"` → creates a session.
- `app.secret_key` → signs cookie so it can’t be forged.
- `permanent_session_lifetime = 5 minutes` → timeout enforced.
- `/logout` → deletes session.

---

## Expected Output

- Before login → “Hello! Please login”.
- After login → “Welcome back, student123! (Session Active)”.
- After logout → “Logged out. Home”.
- Session auto-expires after 5 minutes inactivity.

---

## Mitigations Summary

- Use **HTTPS-only, HttpOnly, SameSite cookies**.
- Set **timeouts & regeneration** of session IDs.
- Never store sensitive data directly in session (store only session ID).
- Use secure frameworks (Flask, Express, Django) which handle session tokens correctly.

1. Basic flow (login → session)

Click Login (or visit /login).

After login, show the page: it should say Welcome back, student123!.

Explain: session data (user, created_by) is stored server-side (in filesystem folder) and browser only holds a signed cookie that references the server-side session.

Screenshot to take:

The page after login showing Welcome back, student123!.

2. Show cookies in browser devtools

Open Developer Tools → Application (Chrome) or Storage (Firefox) → Cookies → select http://127.0.0.1:5000.

Show the cookie(s). Key points to highlight:

Cookie name (Flask session cookie usually session or session=<value>).

HttpOnly — prevents JS from accessing cookie.

SameSite — prevents some CSRF.

Secure — currently OFF (because local), explain to teacher that in production it should be True (HTTPS).

Screenshot to take:

DevTools cookie pane showing flags (HttpOnly, SameSite, Secure).

3. Show raw response headers with curl

Use terminal to show Set-Cookie header:

# Inspect headers when hitting /inspect_headers

curl -I http://127.0.0.1:5000/inspect_headers

---

In the Set-Cookie header, point out HttpOnly and SameSite=Lax.

Example output (what to highlight):

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 36
Set-Cookie: inspect_demo=1; Path=/; Max-Age=300; HttpOnly; SameSite=Lax

4. Demonstrate logout & expiry

Click /logout to clear session.

Try going to / again — it should prompt login.

Show that session files in ./flask_session_files were created at login and removed/cleared on logout (server-side evidence).

Screenshot to take:

Terminal listing ./flask_session_files before and after logout (or show file timestamps).

5. Session Fixation mitigation demo (explain verbally & show behavior)

Explain session fixation: attacker sets a session ID before victim logs in.

Show mitigation used: create_session_for_user() clears old session before setting session['user'] → this prevents reusing a pre-known session ID.

Optionally, emphasize that in production frameworks you should "rotate" the session id on login (call framework API to regenerate id).

Extra points to explain to teacher (short bullets)

Use SESSION_COOKIE_HTTPONLY = True to prevent JS theft (XSS).

Use SESSION_COOKIE_SECURE = True when serving via HTTPS to avoid sending cookie over HTTP.

Use SESSION_COOKIE_SAMESITE = 'Lax' or 'Strict' to mitigate CSRF.

Prefer server-side session stores (Redis, DB) so cookies contain only a session id, not whole state.

Regenerate session id on login to mitigate fixation.

Commands to capture during demo (copy-paste)

Start app:

python exp7_secure_sessions.py

Show response headers:

curl -I http://127.0.0.1:5000/inspect_headers

Show cookie sent by browser (use browser devtools).

Show server-side session files:

ls -la ./flask_session_files
