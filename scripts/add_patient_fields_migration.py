"""Simple migration helper: add optional encrypted patient columns to SQLite DB.
Run this locally (make a DB backup first). It will add new columns to `patients` table
if they are not present.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'clinic.db')

if not os.path.exists(DB_PATH):
    print('Database not found at', DB_PATH)
    print('Update DB_PATH if your DB is elsewhere.')
    raise SystemExit(1)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

existing = set(r[1] for r in cur.execute("PRAGMA table_info(patients);").fetchall())

columns = [
    ('encrypted_gender', 'BLOB'),
    ('encrypted_address', 'BLOB'),
    ('encrypted_city', 'BLOB'),
    ('encrypted_country', 'BLOB'),
    ('encrypted_postal_code', 'BLOB'),
    ('encrypted_occupation', 'BLOB'),
    ('encrypted_nationality', 'BLOB'),
    ('encrypted_marital_status', 'BLOB'),
    ('encrypted_height_cm', 'BLOB'),
    ('encrypted_weight_kg', 'BLOB'),
    ('encrypted_id_number', 'BLOB'),
    ('encrypted_preferred_language', 'BLOB'),
]

for name, ctype in columns:
    if name in existing:
        print(f"Column {name} already exists, skipping")
        continue
    sql = f"ALTER TABLE patients ADD COLUMN {name} {ctype};"
    print('Adding column:', name)
    cur.execute(sql)

conn.commit()
conn.close()
print('Migration complete. Please restart your app.')
