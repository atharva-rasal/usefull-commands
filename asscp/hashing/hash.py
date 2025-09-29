import bcrypt, hashlib, os

# --- Bcrypt Example ---
password = b"mySecret123"

# Hash password
hashed_bcrypt = bcrypt.hashpw(password, bcrypt.gensalt())
print("Bcrypt Hashed:", hashed_bcrypt)

# Verify password
print("Bcrypt Check (correct):", bcrypt.checkpw(password, hashed_bcrypt))
print("Bcrypt Check (wrong):", bcrypt.checkpw(b"wrongpass", hashed_bcrypt))


# --- PBKDF2 Example ---
salt = os.urandom(16)
hashed_pbkdf2 = hashlib.pbkdf2_hmac('sha256', password, salt, 200000)

print("\nPBKDF2 Hashed (hex):", (salt+hashed_pbkdf2).hex())

# Verify password
new_key = hashlib.pbkdf2_hmac('sha256', password, salt, 200000)
print("PBKDF2 Check (correct):", new_key == hashed_pbkdf2)

wrong_key = hashlib.pbkdf2_hmac('sha256', b"wrongpass", salt, 200000)
print("PBKDF2 Check (wrong):", wrong_key == hashed_pbkdf2)
