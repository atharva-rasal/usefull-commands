````markdown
# Experiment 9 — JSON Web Token (JWT) Demo

## Objective

Show how JWT can be used for stateless authentication:

- Server generates a signed token on login.
- Client sends token with every request.
- Server validates token signature and expiration.

---

## 🔧 Setup & Run

### 1. Create Virtual Environment (Windows PowerShell / VS Code Terminal)

```powershell
python -m venv venv
venv\Scripts\activate
```
````

### 2. Install Dependencies

```powershell
pip uninstall jwt -y   # remove wrong package if installed
pip install Flask PyJWT
```

### 3. Save Code

Save the Flask app as `exp9_jwt_demo.py`:

```python
from flask import Flask, request, jsonify
import jwt, datetime, os

app = Flask(__name__)
SECRET_KEY = os.urandom(24)  # secret key for signing tokens

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    if username != "student123":
        return jsonify({"error": "Invalid user"}), 401

    payload = {
        "user": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"message": f"Welcome {data['user']}! Token valid."})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(port=5000, debug=True)
```

### 4. Run the Server

```powershell
python exp9_jwt_demo.py
```

Server runs at: `http://127.0.0.1:5000`

---

## 🧪 Testing with Postman

### 1. Login → Get Token

- Method: **POST**
- URL: `http://127.0.0.1:5000/login`
- Body → Raw → JSON:

```json
{
  "username": "student123"
}
```

- Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 2. Access Protected Route

- Method: **GET**

- URL: `http://127.0.0.1:5000/protected`

- Headers:

  - **Key:** Authorization
  - **Value:** Paste the token you got from `/login`

- Response (if valid):

```json
{
  "message": "Welcome student123! Token valid."
}
```

---

### 3. Test Security

- If you send no token → returns:

```json
{ "error": "Missing token" }
```

- If you send wrong token → returns:

```json
{ "error": "Invalid token" }
```

- If token expires (after 5 min) → returns:

```json
{ "error": "Token expired" }
```

---

## ✅ Viva Points

- JWT = Header + Payload + Signature.
- Signed with secret (HS256).
- Stateless → server does not store session data.
- Must set expiry (`exp`) to prevent misuse.
- Widely used in APIs and OAuth2 authentication.

```

```
