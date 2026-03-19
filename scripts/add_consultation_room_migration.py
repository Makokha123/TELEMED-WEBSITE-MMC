"""
Migration: Add consultation_rooms table
Run from project root:
    python scripts/add_consultation_room_migration.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from sqlalchemy import inspect, text


def run():
    with app.app_context():
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()

        if 'consultation_rooms' in existing_tables:
            print("[migration] consultation_rooms table already exists – skipping.")
            return

        print("[migration] Creating consultation_rooms table …")
        db.session.execute(text("""
            CREATE TABLE consultation_rooms (
                id                         INTEGER PRIMARY KEY AUTOINCREMENT,
                appointment_id             INTEGER NOT NULL UNIQUE,
                room_token                 VARCHAR(128) NOT NULL UNIQUE,
                status                     VARCHAR(20)  NOT NULL DEFAULT 'waiting',
                is_group_session           BOOLEAN      NOT NULL DEFAULT 0,
                group_appointment_ids      TEXT,
                unlock_at                  DATETIME     NOT NULL,
                lock_at                    DATETIME     NOT NULL,
                started_at                 DATETIME,
                ended_at                   DATETIME,
                created_at                 DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at                 DATETIME,
                ended_by_user_id           INTEGER,
                session_notes              TEXT,
                recording_consent_doctor   BOOLEAN      NOT NULL DEFAULT 0,
                recording_consent_patient  BOOLEAN      NOT NULL DEFAULT 0,
                FOREIGN KEY (appointment_id)     REFERENCES appointments(id),
                FOREIGN KEY (ended_by_user_id)   REFERENCES users(id)
            )
        """))

        # Indexes
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_consultation_rooms_appointment_id "
            "ON consultation_rooms (appointment_id)"
        ))
        db.session.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_consultation_rooms_room_token "
            "ON consultation_rooms (room_token)"
        ))

        db.session.commit()
        print("[migration] Done. consultation_rooms table created successfully.")


if __name__ == '__main__':
    run()
