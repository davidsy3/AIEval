import os
import sqlite3

# Hardcoded secret
API_KEY = os.environ.get("API_KEY")


def run_backup(filename):
    # Command injection: filename is passed straight into a shell command
    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename.startswith("-"):
        raise ValueError("Invalid filename")
    subprocess.run(["tar", "-cvf", "backup.tar", "--", safe_filename], check=True)


def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL injection: user input concatenated directly into the query
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()


def read_upload(user_path):
    # Unsanitized file path: no check against directory traversal
    upload_dir = os.path.realpath("/uploads")
    candidate = os.path.realpath(os.path.join(upload_dir, os.path.basename(user_path)))
    if not candidate.startswith(upload_dir + os.sep):
        raise ValueError("Invalid path")
    with open(candidate) as f:
        return f.read()