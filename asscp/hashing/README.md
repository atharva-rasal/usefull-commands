# Password Hashing Techniques: Bcrypt vs PBKDF2

## Why Hash Passwords?

- Storing plain text passwords is dangerous — if the database leaks, all user accounts are exposed.
- Hashing converts passwords into irreversible fixed-length strings.
- Modern secure hash functions make brute force and rainbow table attacks harder.

---

## 1. Bcrypt

**Description:**

- A password hashing function based on the Blowfish cipher (1999).
- Automatically handles **salt generation** internally.
- Uses an adjustable **cost factor (work factor)** that controls how slow hashing is → makes brute-force harder as hardware improves.

**Key Features:**

- Built-in salt (no need to manage manually).
- Adaptive cost → can be increased as computers get faster.
- Produces a hash like:

**Advantages:**

- Easy to implement, widely supported.
- Resistant to rainbow table attacks.
- Slows down brute force attempts.

**Limitations:**

- Slower than general-purpose hashing, but that’s intentional.
- Not as modern as Argon2 (but still widely trusted).

---

## 2. PBKDF2 (Password-Based Key Derivation Function 2)

**Description:**

- A standard algorithm (PKCS #5, RFC 2898).
- Uses **HMAC with a hash function** (e.g., SHA-256).
- Requires a **salt** (stored separately) and an **iteration count** (work factor).
- Often used in enterprise systems and libraries.

**Key Features:**

- You choose salt (random bytes) and iteration count.
- Produces derived keys that can also be used for encryption keys.
- Hash looks like a binary blob (salt + derived key).

**Advantages:**

- Standardized and available in most programming languages.
- Flexible: can use SHA-1, SHA-256, SHA-512 as the underlying hash.
- Widely used in protocols (e.g., WPA2 Wi-Fi, password managers).

**Limitations:**

- Faster than bcrypt → less resistant to GPU attacks unless iteration count is very high.
- Developers must manage salt and iterations manually.

---

## Comparison Table

| Feature          | Bcrypt                   | PBKDF2                         |
| ---------------- | ------------------------ | ------------------------------ |
| Salt handling    | Built-in, automatic      | Must be provided manually      |
| Work factor      | Cost factor (e.g., 12)   | Iteration count (e.g., 200k+)  |
| Underlying basis | Blowfish cipher          | HMAC with SHA-x                |
| Speed            | Intentionally slow       | Faster, but tunable            |
| Security level   | Strong, widely trusted   | Strong if iterations are high  |
| Typical usage    | Web apps, authentication | Enterprises, Wi-Fi, key deriv. |

---

## Best Practices

- Always use **bcrypt, PBKDF2, or Argon2** (not plain MD5/SHA-1).
- Choose high work factor / iteration count:
- Bcrypt: cost factor 12+.
- PBKDF2: ≥200,000 iterations (adjust with hardware).
- Store salt alongside hash (if not built-in).
- Use a modern library instead of writing your own low-level code.

---
