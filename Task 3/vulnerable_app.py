"""
vulnerable_app.py
------------------
Sample Python application used for the Secure Coding Review (Task 3).

WARNING: This file is written DELIBERATELY with common security flaws
so they can be identified during the review. Do NOT use this code in
production. See SECURITY_REVIEW_REPORT.md for the findings and
fixed_app.py for the corrected version.
"""

import sqlite3
import hashlib
import os
import pickle

# --- Vulnerability 1: Hardcoded credentials / secret key ---
DB_PASSWORD = "admin123"
SECRET_KEY = "s3cr3t-key-12345"


def get_db_connection():
    conn = sqlite3.connect("users.db")
    return conn


def create_user_table():
    conn = get_db_connection()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT, password TEXT)"
    )
    conn.commit()
    conn.close()


# --- Vulnerability 2: SQL Injection (string formatting into query) ---
def get_user(username):
    conn = get_db_connection()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = conn.execute(query)
    return cursor.fetchone()


# --- Vulnerability 3: Weak hashing algorithm for passwords (MD5) ---
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# --- Vulnerability 4: Command Injection via os.system ---
def ping_host(host):
    os.system("ping -c 1 " + host)


# --- Vulnerability 5: Insecure Deserialization ---
def load_session(data):
    return pickle.loads(data)


# --- Vulnerability 6: Use of eval() on user input ---
def calculate(expression):
    return eval(expression)


# --- Vulnerability 7: Overly permissive file write / path traversal ---
def save_upload(filename, content):
    path = "uploads/" + filename
    with open(path, "w") as f:
        f.write(content)


if __name__ == "__main__":
    create_user_table()
    print("Vulnerable demo app initialized.")
