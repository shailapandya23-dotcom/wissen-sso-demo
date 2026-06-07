import sqlite3
import os

from .config import DB_PATH

EMPLOYEES = [
    ("Shaila Pandya", "shaila.pandya@wissen.com", "shaila123"),
    ("Rahul Pandey", "rahul.pandey@wissen.com", "rahul456"),
    ("Nandini Sharma", "nandini.sharma@wissen.com", "nandini000"),
    ("Krishna Kaushik", "krishna.kaushik@wissen.com", "krishna444"),
    ("Aadya Billore", "aadya.billore@wissen.com", "aadya888"),
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)
    existing = c.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    if existing == 0:
        c.executemany(
            "INSERT INTO employees (name, email, password) VALUES (?, ?, ?)",
            EMPLOYEES,
        )
        conn.commit()
        print(f"Database initialized with {len(EMPLOYEES)} employees at {DB_PATH}")
    else:
        print(f"Database already has {existing} employees at {DB_PATH}")
    conn.close()


if __name__ == "__main__":
    init_db()
