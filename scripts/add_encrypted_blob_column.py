#!/usr/bin/env python3
"""
Add `encrypted_file_blob` column to `communications` table if it doesn't exist.
Run from project root with your venv python, e.g.:
  myenv\Scripts\python.exe .\scripts\add_encrypted_blob_column.py
"""
import sys
from pathlib import Path

# make sure project root is importable
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

from app import app, db
from sqlalchemy import text

with app.app_context():
    print('Connected to DB engine:', db.engine)
    try:
        with db.engine.connect() as conn:
            res = conn.execute(text("PRAGMA table_info('communications')"))
            cols = [row[1] for row in res.fetchall()]
    except Exception as e:
        print('Failed to query PRAGMA table_info:', e)
        sys.exit(2)

    print('Existing columns in communications:', cols)
    if 'encrypted_file_blob' in cols:
        print('Column `encrypted_file_blob` already exists. Nothing to do.')
        sys.exit(0)

    try:
        print('Adding column `encrypted_file_blob` as BLOB...')
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE communications ADD COLUMN encrypted_file_blob BLOB'))
            # some dialects may require a commit on the connection
            try:
                conn.execute(text('COMMIT'))
            except Exception:
                pass
        print('ALTER TABLE executed; column added.')
    except Exception as e:
        print('Failed to add column via ALTER TABLE:', e)
        sys.exit(3)

    # optional verification
    try:
        with db.engine.connect() as conn:
            res2 = conn.execute(text("PRAGMA table_info('communications')"))
            cols2 = [row[1] for row in res2.fetchall()]
    except Exception as e:
        print('Verification failed:', e)
        sys.exit(5)

    print('Updated columns:', cols2)
    if 'encrypted_file_blob' in cols2:
        print('Success: column present.')
        sys.exit(0)
    else:
        print('Column still missing after ALTER TABLE. Manual migration required.')
        sys.exit(4)
