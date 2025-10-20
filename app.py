import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

DB_PATH = os.path.join(os.path.dirname(__file__), "verysecuredatabase.db")
print("USING DB:", DB_PATH)

app = Flask(__name__)
app.secret_key = "dev-key"
app.debug = True

# Rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv("RATE_LIMIT_STORAGE", "memory://"),
    strategy="moving-window",
    default_limits=[],
)
limiter.init_app(app)

MAX_ATTEMPTS = 3
LOCK_SECONDS = 5 * 60
WINDOW_SECONDS = 10 * 60

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_tables():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password BLOB NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_throttle (
                username TEXT NOT NULL,
                ip       TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt INTEGER NOT NULL,
                locked_until INTEGER,
                PRIMARY KEY (username, ip)
            )
        """)
ensure_tables()

# Throttle
def now_ts() -> int:
    return int(time.time())

def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unkown")

def get_throttle_row(conn, username, ip):
    cur = conn.execute(
        "SELECT attempts, last_attempt, locked_until FROM login_throttle WHERE username=? AND ip=?",
        (username, ip),
    )
    return cur.fetchone()

def set_throttle(conn, username, ip, attempts, last_attempt, locked_until):
    conn.execute(
        """
        INSERT INTO login_throttle (username, ip, attempts, last_attempt, locked_until)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT(username, ip) DO
        UPDATE SET
            attempts=excluded.attempts,
            last_attempt=excluded.last_attempt,
            locked_until=excluded.locked_until
        """,
        (username, ip, attempts, last_attempt, locked_until),
    )

def clear_throttle(conn, username, ip):
    conn.execute("DELETE FROM login_throttle WHERE username=? AND ip=?", (username, ip))

def is_locked(conn, username, ip):
    row = get_throttle_row(conn, username, ip)
    if not row:
        return 0
    attempts, last_attempt, locked_until = row
    ts = now_ts()
    if locked_until and locked_until > ts:
        return locked_until - ts
    if last_attempt and (ts - last_attempt) > WINDOW_SECONDS:
        clear_throttle(conn, username, ip)
    return 0

def failed_attempts(conn, username, ip):
    row = get_throttle_row(conn, username, ip)
    ts = now_ts()
    if not row:
        attempts = 1
        locked_until = None
    else:
        attempts, last_attempt,  locked_until = row
        if ts - last_attempt > WINDOW_SECONDS:
            attempts = 0
        attempts += 1

    if attempts >= MAX_ATTEMPTS:
        set_throttle(conn, username, ip, 0, ts, ts + LOCK_SECONDS)
    else:
        set_throttle(conn, username, ip, attempts, ts, None)

@app.route('/')
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Hash the password
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        conn.close()

        return redirect(url_for("login"))
    return render_template("register.html")

def username_key():
    return (request.form.get("username") or "").strip().lower()

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
@limiter.limit("100 per hour")
@limiter.limit("5 per 15 minutes", key_func=username_key)
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password", "")
        ip = client_ip()

        with get_db() as conn:
            # Check lock state
            remaining = is_locked(conn, username, ip)
            if remaining > 0:
                minutes = max(1, remaining // 60)
                # 429 signals throttling to clients/tools
                return render_template(
                    "login.html",
                    error=f"Too many attempts. Try again in ~{minutes} minute(s)."
                ), 429

            # Fetch user
            cur = conn.execute("SELECT username, password FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

            ok = bool(user) and bcrypt.checkpw(password.encode("utf-8"), user["password"])

            if ok:
                session["username"] = user["username"]
                clear_throttle(conn, username, ip)
                return redirect(url_for("dashboard"))
            else:
                failed_attempts(conn, username, ip)
                return render_template("login.html", error="Invalid credentials"), 401

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)