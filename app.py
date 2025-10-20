from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import bcrypt
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "verysecuredatabase.db")
print("USING DB:", DB_PATH)

app = Flask(__name__)
# Use an environment variable for the secret key in production; fallback to a random key for dev
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)
app.debug = True


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("register.html", error="Username and password are required")

        conn = get_db()
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            conn.close()
            return render_template("register.html", error="Username already taken")
        rounds = int(os.environ.get("BCRYPT_ROUNDS", "12"))
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds)).decode('utf-8')
        created_at = datetime.now(timezone.utc).isoformat()

        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, created_at),
        )
        conn.commit()
        conn.close()

        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
            # reset failed attempts on success
            conn.execute("UPDATE users SET failed_login_attempts = 0 WHERE id = ?", (user["id"],))
            conn.commit()
            conn.close()

            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        # increment failed attempts if user exists
        if user:
            conn.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?", (user["id"],))
            conn.commit()
        conn.close()

        return render_template("login.html", error="Invalid credentials")
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