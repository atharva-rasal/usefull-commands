from flask import Flask, request, jsonify
import os, uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Upload config
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "pdf"}
MAX_SIZE = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_DIR, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files['file']
    if f.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(f.filename):
        return jsonify({"error": "Invalid file type"}), 400

    # Check size (move cursor to end)
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(0)
    if size > MAX_SIZE:
        return jsonify({"error": "File too large"}), 400

    # Rename file securely
    ext = f.filename.rsplit('.', 1)[1].lower()
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    save_path = os.path.join(UPLOAD_DIR, secure_filename(safe_name))

    f.save(save_path)
    os.chmod(save_path, 0o600)  # remove execute permissions

    return jsonify({"message": "Upload successful", "filename": safe_name}), 201

if __name__ == '__main__':
    app.run(port=5000, debug=True)
