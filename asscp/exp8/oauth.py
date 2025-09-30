"""
exp8_oauth_demo.py
Simple Flask OAuth2.0 demo with GitHub.
"""

from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure OAuth client
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id="aaaaaaa",          # replace with your GitHub OAuth App Client ID
    client_secret="aaaaaa",  # replace with your GitHub OAuth App Client Secret
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

@app.route('/')
def index():
    user = session.get('user')
    if user:
        return f"✅ Logged in as {user['login']} (GitHub)<br><a href='/logout'>Logout</a>"
    return "Hello! Please <a href='/login'>Login with GitHub</a>"

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = github.authorize_access_token()
    user = github.get('user').json()
    session['user'] = user
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return "Logged out.<br><a href='/'>Home</a>"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
