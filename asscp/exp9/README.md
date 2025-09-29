Perfect 👍 let’s wrap this up with a **Markdown guide for Secure File Upload (Experiment 10)** — including a **short Flask demo code**, **run steps for Windows (VS Code + PowerShell)**, and **Postman test steps** you can show to your teacher.

---

### File: `Exp10_Secure_File_Upload.md`

````markdown
# Experiment 10 — Secure File Upload

## Objective

Show how to securely handle file uploads in a web app:

- Restrict allowed file types
- Store files outside the webroot
- Rename files to prevent overwriting or path traversal
- Remove execute permissions

---

## 🔧 Setup & Run

### 1. Create Virtual Environment (Windows PowerShell / VS Code)

```powershell
python -m venv venv
venv\Scripts\activate
```
````

### 2. Install Dependencies

```powershell
pip install Flask
```

### 3. Save Code

Save this as `exp10_file_upload.py`:

```python
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
```

### 4. Run the Server

```powershell
python exp10_file_upload.py
```

Server runs at: `http://127.0.0.1:5000/upload`

---

## 🧪 Testing with Postman

### 1. Upload a Valid File

- Method: **POST**
- URL: `http://127.0.0.1:5000/upload`
- Go to **Body → form-data**

  - Add a new key: `file` (set type to _File_)
  - Choose a file (e.g., `sample.pdf`)

**Expected Response**

```json
{
  "message": "Upload successful",
  "filename": "e2b1c1e6a3f44f3e8f...pdf"
}
```

---

### 2. Upload Invalid File Type

Try uploading `malware.exe`

**Expected Response**

```json
{
  "error": "Invalid file type"
}
```

---

### 3. Upload Large File (>5MB)

**Expected Response**

```json
{
  "error": "File too large"
}
```

---

## ✅ Security Best Practices

- **Whitelist extensions** (`png, jpg, pdf`) → block executables/scripts.
- **Rename files** using UUIDs → avoid overwriting & path traversal.
- **Store outside webroot** → prevent direct execution.
- **Remove execute permissions** (`chmod 600`).
- **Limit file size** → avoid denial of service.
- **Scan uploads** (e.g., ClamAV) in real-world apps.

---

## Expected Exam Demo

1. Upload safe file → “Upload successful”.
2. Upload `.exe` → blocked.
3. Upload >5MB file → blocked.
4. Show `uploads/` folder with renamed files.

```

---
```
