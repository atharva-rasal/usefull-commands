# 🧑‍💻 Steps to Run the OAuth2 Demo (GitHub Login)

1. **Create GitHub OAuth App**

   - Go to [GitHub Developer Settings → OAuth Apps](https://github.com/settings/developers).
   - Click **New OAuth App** → Fill details:

     - Application name: `OAuth2 Demo`
     - Homepage URL: `http://127.0.0.1:5000/`
     - Authorization callback URL: `http://127.0.0.1:5000/authorize`

   - Save → copy **Client ID** and **Client Secret**.

2. **Install Python requirements**

   ```bash
   pip install Flask Authlib
   ```

3. **Save Flask app** as `exp8_oauth_demo.py` and replace:

   ```python
   client_id="YOUR_CLIENT_ID"
   client_secret="YOUR_CLIENT_SECRET"
   ```

4. **Run the app**

   ```bash
   python exp8_oauth_demo.py
   ```

   Flask starts on: `http://127.0.0.1:5000/`

5. **Test the flow**

   - Open browser → `http://127.0.0.1:5000/`
   - Click **Login with GitHub**
   - GitHub login screen appears → Authorize app
   - Redirects back → Page shows:
     ✅ Logged in as `<your-username>`
   - Click **Logout** to clear session.

6. **Show teacher**

   - Show GitHub login popup (proof of OAuth).
   - Show after redirect your username is displayed.
   - Explain: _“My app never asked for a password. It got a token from GitHub, then fetched my profile using OAuth2.”_

---

# 📘 Markdown Theory (save as `Exp8_OAuth2.md`)

```markdown
# Experiment 8 — OAuth 2.0 (GitHub Login Demo)

## Objective

Demonstrate how OAuth 2.0 allows third-party apps to authenticate users using trusted providers (e.g., GitHub, Google) without handling their password.

---

## What is OAuth 2.0?

- An **authorization framework** that lets apps obtain limited access to user resources.
- Instead of giving password to app → user gives **consent** to provider (GitHub).
- Provider gives back an **Access Token** → app uses it to access user profile or data.

---

## Key Roles

1. **Resource Owner (User)** → grants permission.
2. **Client (App)** → requests access.
3. **Authorization Server (GitHub)** → authenticates user & issues token.
4. **Resource Server (GitHub API)** → returns user data when given a valid token.

---

## Authorization Code Flow (used here)

1. User clicks _Login with GitHub_.
2. App redirects to GitHub’s **Authorize URL**.
3. User logs in → GitHub asks for consent.
4. GitHub redirects back with a **code**.
5. App exchanges code for an **Access Token**.
6. App uses token to fetch profile → user logged in.

---

## Demo Highlights

- `/login` → redirects to GitHub OAuth page.
- `/authorize` → receives code, exchanges for token, stores session.
- `/` → shows GitHub username if logged in.
- `/logout` → clears session.

---

## Expected Output

- Before login → “Hello! Please Login with GitHub”.
- After login → “✅ Logged in as <username> (GitHub)”.
- Logout → “Logged out. Home”.

---

## Security Best Practices

- Always use **HTTPS** in production.
- Store `client_secret` securely (not in code).
- Use **short-lived access tokens** + refresh tokens.
- Request **minimum scopes** (e.g., `user:email` only).
```

---

👉 This gives you **practical demo steps** + **theory explanation** (both ready for viva/exam).

Do you want me to now prepare the **Exp 9 — JWT (JSON Web Token)** in the same style (Python demo + run steps + markdown theory)?
