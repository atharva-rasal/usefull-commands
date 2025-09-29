"""
exp7_secure_sessions.py
Simple, exam-friendly Flask app that demonstrates secure session management & cookies.

Features:
- Secure cookie config (HttpOnly, SameSite)
- Demonstrates clearing session before login (mitigates fixation)
- Optional server-side session storage using Flask-Session (filesystem)
- Endpoints to inspect Set-Cookie header and current session state
- Easy to run locally (no HTTPS required for demo). When on real server, set SESSION_COOKIE_SECURE=True.
"""

from flask import Flask, session, request, redirect, url_for, make_response, jsonify
from datetime import timedelta
import os
from flask_session import Session   # pip install Flask-Session

app = Flask(__name__)

# Secret used to sign cookies
app.secret_key = os.urandom(24)

# Session config
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
# Cookie security flags (for local demo set SECURE=False; set to True on HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True   # hides cookie from JS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # 'Strict' or 'Lax' recommended
app.config['SESSION_COOKIE_SECURE'] = False    # True if served over HTTPS

# --- Optional: server-side sessions (safer than cookie-only session)
# Stores session data on filesystem instead of serializing everything into client cookie.
# This allows you to keep only a session id in cookie (safer).
app.config['SESSION_TYPE'] = 'filesystem'     # 'redis' in production is better
app.config['SESSION_FILE_DIR'] = './flask_session_files'
app.config['SESSION_PERMANENT'] = True

Session(app)  # bind Flask-Session

# --- Helpers ---
def create_session_for_user(username: str):
    """
    Mitigate fixation by clearing old session first, then setting new session data.
    This approximates "regenerate session id" behavior in frameworks.
    """
    # Clear any existing session data (prevent fixation where attacker sets session prior)
    session.clear()
    # Create new session
    session['user'] = username
    session.permanent = True  # obey PERMANENT_SESSION_LIFETIME
    # Add a little non-sensitive metadata to show server-side storage
    session['created_by'] = 'exp7_demo'
    return

# --- Routes ---
@app.route('/')
def index():
    if 'user' in session:
        return (
            f"Welcome back, {session['user']}!<br>"
            f"Session created_by: {session.get('created_by')}<br>"
            f"<a href='/show_cookies'>Show cookies (raw)</a> | "
            f"<a href='/logout'>Logout</a>"
        )
    return "Hello! You are not logged in. <a href='/login'>Login</a>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    # In a real app you'd verify username/password from DB.
    # For demo: call POST to simulate login; GET also logs in a demo user
    username = request.form.get('username') or 'student123'
    # Mitigation: clear previous session (prevent session fixation)
    create_session_for_user(username)
    # After login, return a response that shows Set-Cookie header for teaching
    resp = make_response(redirect(url_for('index')))
    # Add an extra test cookie (HttpOnly still set by app config)
    resp.set_cookie('demo_info', 'logged_in_demo', max_age=300, httponly=True, samesite='Lax')
    return resp

@app.route('/logout')
def logout():
    session.clear()
    # clear demo_info cookie as well
    resp = make_response("Logged out. <a href='/'>Home</a>")
    resp.set_cookie('demo_info', '', expires=0)
    return resp

@app.route('/show_cookies')
def show_cookies():
    """
    Returns the raw Set-Cookie headers (if any) for the previous response
    and shows the current session contents (server-side).
    This endpoint helps show teacher the cookie behavior.
    """
    # Show cookie values as stored in browser request (not secure to show in production)
    request_cookies = dict(request.cookies)
    server_session = {k: session.get(k) for k in session.keys()}
    return jsonify({
        "request_cookies_sent_by_browser": request_cookies,
        "server_session_data": server_session
    })

@app.route('/inspect_headers')
def inspect_headers():
    """
    Endpoint that returns a response but also prints Set-Cookie header values you can capture via curl -I.
    """
    resp = make_response("Inspect headers - this response sets a demo cookie")
    # set a demonstrative cookie with flags
    resp.set_cookie('inspect_demo', '1', httponly=True, samesite='Lax', max_age=300)
    return resp

if __name__ == '__main__':
    # Ensure session file dir exists
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    # Run in debug for local demo; in real deployment remove debug and run behind HTTPS
    app.run(host='127.0.0.1', port=5000, debug=True)
