"""
fixed_app.py
------------------
Secure, remediated version of vulnerable_app.py.
Each fix maps to a finding in SECURITY_REVIEW_REPORT.md.
"""

import sqlite3
import hashlib
import hmac
import os
import ast
import subprocess
import secrets

# --- Fix 1: Load secrets from environment variables, never hardcode ---
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))


def get_db_connection():
    conn = sqlite3.connect("users.db")
    return conn


def create_user_table():
    conn = get_db_connection()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT, password_hash TEXT, salt TEXT)"
    )
    conn.commit()
    conn.close()


# --- Fix 2: Parameterized query prevents SQL Injection ---
def get_user(username):
    conn = get_db_connection()
    cursor = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    )
    return cursor.fetchone()


# --- Fix 3: Strong salted hashing (PBKDF2-HMAC-SHA256) instead of MD5 ---
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 100_000
    )
    return hashed.hex(), salt


def verify_password(password, salt, stored_hash):
    new_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(new_hash, stored_hash)


# --- Fix 4: No shell invocation; validate input, use subprocess with a list ---
def ping_host(host):
    # Basic allow-list validation: only letters, digits, dots, hyphens
    import re
    if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        raise ValueError("Invalid host")
    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True, timeout=5
    )
    return result.stdout


# --- Fix 5: Never unpickle untrusted data; use JSON instead ---
import json


def load_session(data):
    return json.loads(data)


# --- Fix 6: Replace eval() with a safe expression evaluator ---
def calculate(expression):
    # ast.literal_eval only parses literals, not arbitrary code
    return ast.literal_eval(expression)


# --- Fix 7: Sanitize filename / prevent path traversal ---
def save_upload(filename, content):
    safe_name = os.path.basename(filename)  # strips any ../ path segments
    upload_dir = os.path.abspath("uploads")
    path = os.path.join(upload_dir, safe_name)
    if not path.startswith(upload_dir):
        raise ValueError("Invalid filename")
    os.makedirs(upload_dir, exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


if __name__ == "__main__":
    create_user_table()
    print("Secure demo app initialized.")
