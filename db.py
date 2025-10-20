import sqlite3
from datetime import datetime
import os
import bcrypt


def create_and_populate_db(db_name="verysecuredatabase.db"):
    rounds = int(os.environ.get("BCRYPT_ROUNDS", "12")) # 11 is like 0.1s 12 is like 0.2s 13 is like 0.4s
    with sqlite3.connect(db_name) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0
            );
        """)

        # Insert sample users with bcrypt-hashed passwords (INSERT OR IGNORE avoids duplicates)
        samples = [
            ("John", bcrypt.hashpw(b"nothacker", bcrypt.gensalt(rounds)).decode('utf-8')),
            ("Kai", bcrypt.hashpw(b"superhacker", bcrypt.gensalt(rounds)).decode('utf-8')),
            ("Kai2", bcrypt.hashpw(b"giveauthorizationpls", bcrypt.gensalt(rounds)).decode('utf-8')),
        ]

        cursor.executemany(
            "INSERT OR IGNORE INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            [(u, p, datetime.utcnow().isoformat()) for u, p in samples],
        )

        conn.commit()
        print("Database created successfully")

