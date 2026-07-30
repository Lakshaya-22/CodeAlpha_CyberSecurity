# Task 3: Secure Coding Review

**CodeAlpha Cyber Security Internship**

## Overview

**Language / Application audited:** Python (`vulnerable_app.py`) — a small
sample application simulating a user authentication + file upload service.

**Method used:**
- Static analysis with **Bandit** (`bandit vulnerable_app.py`)
- Manual code inspection line-by-line

## Summary of Findings

| # | Vulnerability | Severity | CWE |
|---|---|---|---|
| 1 | Hardcoded credentials / secret key | Low | CWE-259 |
| 2 | SQL Injection (string-concatenated query) | Medium | CWE-89 |
| 3 | Weak hashing algorithm (MD5) for passwords | High | CWE-327 |
| 4 | Command Injection via `os.system()` | High | CWE-78 |
| 5 | Insecure Deserialization (`pickle.loads`) | Medium | CWE-502 |
| 6 | Unsafe use of `eval()` on user input | Medium | CWE-78 |
| 7 | Path Traversal in file upload | Medium | CWE-22 |

Full raw Bandit output is in `bandit_report.txt`.

---

## Detailed Findings & Remediation

### 1. Hardcoded Credentials
**Issue:** `DB_PASSWORD` and `SECRET_KEY` are hardcoded as plain strings in
the source file, which get committed to version control.
**Risk:** Anyone with source access (including public GitHub repos) can
read production secrets.
**Fix:** Load secrets from environment variables or a secrets manager
(`os.environ.get(...)`), never commit real credentials.

### 2. SQL Injection
**Issue:** `get_user()` builds a query using string concatenation:
`"SELECT * FROM users WHERE username = '" + username + "'"`.
**Risk:** An attacker can input `' OR '1'='1` to bypass authentication or
extract the entire table.
**Fix:** Use parameterized queries: `conn.execute("SELECT * FROM users
WHERE username = ?", (username,))`.

### 3. Weak Password Hashing
**Issue:** Passwords are hashed with MD5, which is fast and has known
collision weaknesses — practical for attackers to crack via rainbow tables.
**Risk:** If the database leaks, passwords can be recovered quickly.
**Fix:** Use a slow, salted algorithm — PBKDF2-HMAC-SHA256 (or bcrypt/argon2)
with a per-user random salt, as shown in `fixed_app.py`.

### 4. Command Injection
**Issue:** `ping_host()` passes user input directly into `os.system()`.
**Risk:** Input like `8.8.8.8; rm -rf /` executes arbitrary shell commands.
**Fix:** Avoid the shell entirely — use `subprocess.run([...])` with a list
of arguments (no `shell=True`), plus input validation/allow-listing.

### 5. Insecure Deserialization
**Issue:** `load_session()` uses `pickle.loads()` on data that may come
from an untrusted source (e.g., a cookie or network request).
**Risk:** Pickle can execute arbitrary code during deserialization —
a well-known remote code execution vector.
**Fix:** Use a safe serialization format like JSON, which cannot execute code.

### 6. Unsafe `eval()`
**Issue:** `calculate()` runs `eval()` directly on user-supplied input.
**Risk:** Full arbitrary code execution (`eval("__import__('os').system('rm -rf /')")`).
**Fix:** Use `ast.literal_eval()` (only parses literals, not executable code)
or a proper expression-parsing library.

### 7. Path Traversal
**Issue:** `save_upload()` concatenates a user-supplied filename directly
into a file path.
**Risk:** A filename like `../../etc/passwd` can write outside the intended
upload directory.
**Fix:** Strip directory components with `os.path.basename()`, resolve the
final path, and verify it stays inside the upload directory before writing.

---

## General Best Practices Recommended

- Never trust user input — validate, sanitize, or parameterize everywhere
- Keep secrets out of source code (`.env` files + `.gitignore`, or a secrets manager)
- Prefer well-reviewed libraries over hand-rolled crypto or parsing
- Run static analysis (Bandit, Semgrep, or similar) as part of CI/CD
- Apply the principle of least privilege to file system and process access

## Files in this Task

| File | Purpose |
|---|---|
| `vulnerable_app.py` | Original code with intentional vulnerabilities |
| `bandit_report.txt` | Raw static analysis output |
| `fixed_app.py` | Remediated, secure version |
| `SECURITY_REVIEW_REPORT.md` | This report |
