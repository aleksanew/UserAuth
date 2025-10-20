from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "verysecuredatabase.db")
print("USING DB:", DB_PATH)

app = Flask(__name__)
app.secret_key = "dev-key"
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
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
        conn.commit()

        cur = conn.execute("SELECT id, username, password FROM users ORDER BY id DESC LIMIT 1")
        print("JUST SAVED:", cur.fetchone())
        conn.close()

        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        user = cur.fetchone()
        conn.close()

        if user:
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        else:
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