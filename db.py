import sqlite3

def create_and_populate_db(db_name="verysecuredatabase.db"):
    with sqlite3.connect(db_name) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
        """)

        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("John", "nothacker"))
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("Kai", "superhacker"))
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("Kai2", "giveauthorizationpls"))

        conn.commit()
        print(f"Database created successfully")

