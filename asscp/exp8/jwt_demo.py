from flask import Flask, request, jsonify
import jwt, datetime, os

app = Flask(__name__)
SECRET_KEY = os.urandom(24)  # secret key for signing tokens

# Generate JWT
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    # Normally you'd verify username+password from DB
    if username != "student123":
        return jsonify({"error": "Invalid user"}), 401

    payload = {
        "user": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)  # token expires in 5 min
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

# Protected route (requires valid JWT)
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
