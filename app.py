from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import bcrypt
from datetime import datetime, timezone
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp, qrcode, base64, io

DB_PATH = os.path.join(os.path.dirname(__file__), "verysecuredatabase.db")
print("USING DB:", DB_PATH)

app = Flask(__name__)
# Use an environment variable for the secret key in production; fallback to a random key for dev
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)
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

def totp_secret() -> str:
    return pyotp.random_base32()

def totp_uri(username: str, secret: str, issuer: str = "UserAuthApp") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

def qr_data_url(otpauth_uri: str) -> str:
    img = qrcode.make(otpauth_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"

def ensure_tables():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0
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
        if request.form.get("confirm_2fa") == "1":
            username = (request.form.get("username") or "").strip()
            token = (request.form.get("token") or "").strip()
            if not username or not token:
                return render_template("register.html", error="Missing 2FA confirmation fields.")

            with get_db() as conn:
                cur = conn.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
                row = cur.fetchone()
                if not row or not row["totp_secret"]:
                    return render_template("register.html", error="User not found or 2FA not initiated.")
                totp = pyotp.TOTP(row["totp_secret"])
                if totp.verify(token, valid_window=1):
                    conn.execute("UPDATE users SET totp_enabled = 1 WHERE username=?", (username,))
                    return redirect(url_for("login"))
                else:
                    uri = totp_uri(username, row["totp_secret"])
                    qr_url = qr_data_url(uri)
                    return render_template(
                        "register.html",
                        username=username,
                        qr_data_url=qr_url,
                        totop_secret=row["totp_secret"],
                        error="Invalid 2FA code. Try again."
                    )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("register.html", error="Missing username or password.")

        with get_db() as conn:
            cur = conn.execute("SELECT id FROM users WHERE username=?", (username,))
            if cur.fetchone():
                return render_template("register.html", error="Username already in use.")

            rounds = int(os.environ.get("BCRYPT_ROUNDS", "12"))
            salt = bcrypt.gensalt(rounds)  # bytes
            password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
            created_at = datetime.now(timezone.utc).isoformat()

            secret = totp_secret()
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at, totp_secret, totp_enabled) VALUES (?, ?, ?, ?, 0)",
                (username, password_hash, created_at, secret),
            )

            uri = totp_uri(username, secret)
            qr_url = qr_data_url(uri)
            return render_template(
                "register.html",
                username=username,
                qr_data_url=qr_url,
                totp_secret=secret,
            )

    return render_template("register.html")

def username_key():
    return (request.form.get("username") or "").strip().lower()

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
@limiter.limit("100 per hour")
@limiter.limit("5 per 15 minutes", key_func=username_key)
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        token = (request.form.get("token") or "").strip()
        ip = client_ip()
        # Unified login flow: throttle checks + bcrypt verify
        with get_db() as conn:
            # Throttle/lock check
            remaining = is_locked(conn, username, ip)
            if remaining > 0:
                minutes = max(1, remaining // 60)
                return render_template(
                    "login.html",
                    error=f"Too many attempts. Try again in ~{minutes} minute(s)."
                ), 429

            # Fetch user record
            cur = conn.execute("SELECT id, username, password_hash, totp_enabled, totp_secret FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

            ok_pw = bool(user) and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8"))
            if not ok_pw:
                failed_attempts(conn, username, ip)
                if user:
                    conn.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
                                 (user["id"],))
                    conn.commit()
                return render_template("login.html", error="Invalid credentials"), 401

            # If the user has 2FA enabled, require a valid TOTP token
            if user["totp_enabled"]:
                if not token:
                    # Do not reveal whether username exists or has 2FA; just ask for code
                    return render_template("login.html", error="Enter your 6-digit 2FA code."), 401
                totp = pyotp.TOTP(user["totp_secret"])
                if not totp.verify(token, valid_window=1):
                    failed_attempts(conn, username, ip)
                    return render_template("login.html", error="Invalid 2FA code."), 401

            # Success
            conn.execute("UPDATE users SET failed_login_attempts = 0 WHERE id = ?", (user["id"],))
            conn.commit()
            clear_throttle(conn, username, ip)
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

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