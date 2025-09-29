# Experiment 1 – SQL Injection (DVWA)

## Objective

Demonstrate how attackers exploit unsanitized input to retrieve database information.

## Steps

1. **Open DVWA**

   - Login with: `admin` / `password`.
   - Set **DVWA Security Level → Low** under _DVWA Security_ tab.

2. **Navigate to SQL Injection**

   - Left menu → `SQL Injection`.

3. **Inject Payload**

   - In the _User ID_ box, enter:
     ```
     1' OR '1'='1 --
     ```
   - Click **Submit**.

4. **Observe Output**

   - Without injection: only one user’s details are shown.
   - With injection: _all users_ from the database are listed → proving injection.

5. **Screenshot / Evidence**
   - Take screenshot of multiple users being displayed.

## Expected Output

- Database returns all rows instead of one → SQL Injection success.

# SQL Injection — Mitigation (Python & Node.js)

## Objective

Show secure patterns to prevent SQL Injection: use parameterized queries, validate input, and apply least-privilege DB users.

---

## High-level Fixes

- Never build SQL with string concatenation.
- Use parameterized queries / prepared statements or an ORM.
- Validate & whitelist inputs (IDs, enums).
- Use DB users with least privileges.
- Enable DB logging & WAF rules to detect suspicious queries.

---

## Python (sqlite3) — safe example

```python
# safe_sql_py.py
import sqlite3

def get_user_by_id(user_id_str):
    conn = sqlite3.connect('dvwa.db')
    cur = conn.cursor()

    # validate / cast numeric id
    try:
        user_id = int(user_id_str)
    except ValueError:
        raise SystemExit("Invalid ID")

    # parameterized query (no string interpolation)
    cur.execute("SELECT id, first_name, last_name FROM users WHERE id = ?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    import sys
    uid = sys.argv[1] if len(sys.argv) > 1 else "1"
    for r in get_user_by_id(uid):
        print(r)
Node.js (mysql2) — safe example
javascript
Copy code
// safe_sql_js.js
const mysql = require('mysql2/promise');

async function run(userId) {
  const pool = mysql.createPool({
    host: 'localhost',
    user: 'dvwa_user',
    password: 'dvwa_pass',
    database: 'dvwa',
    waitForConnections: true,
    connectionLimit: 5
  });

  const id = Number(userId);
  if (!Number.isInteger(id)) throw new Error('Invalid ID');

  const [rows] = await pool.execute('SELECT id, first_name, last_name FROM users WHERE id = ?', [id]);
  console.log(rows);
  await pool.end();
}

if (require.main === module) {
  run(process.argv[2] || '1').catch(err => { console.error(err.message); process.exit(1); });
}
Server / Config Tips
Limit DB user privileges (no DROP/ALTER).

Use WAF rules to catch injection patterns.

Keep DB & driver libraries up to date.

Log suspicious queries and alert on anomalies.

Quick test (for demo)
Show vulnerable code (string concat) returning all rows for payload: 1' OR '1'='1 --.

Replace with the prepared-statement version above. Run same payload — it should not return extra rows (or should error/validate out).
```
