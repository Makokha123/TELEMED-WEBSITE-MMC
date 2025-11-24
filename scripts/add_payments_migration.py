"""SQLite helper to add `payments` table if missing.
Run locally after backing up your DB.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'clinic.db')

if not os.path.exists(DB_PATH):
    print('Database not found at', DB_PATH)
    raise SystemExit(1)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Check if payments table exists
res = cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='payments';").fetchone()
if res:
    print('payments table already exists')
else:
    print('Creating payments table...')
    cur.execute('''
        CREATE TABLE payments (
            id INTEGER PRIMARY KEY,
            appointment_id INTEGER NOT NULL,
            patient_id INTEGER NOT NULL,
            amount REAL NOT NULL DEFAULT 0.0,
            currency TEXT DEFAULT 'KES',
            provider TEXT,
            provider_reference TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME,
            updated_at DATETIME
        );
    ''')
    conn.commit()
    print('payments table created')

conn.close()
