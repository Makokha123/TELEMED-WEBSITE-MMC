"""
Migration script to add missing columns to the communications table.
This script adds columns that were added to the Communication model but don't exist in the database yet.
"""

import sys
import os

# Add the parent directory to the path to import app and db
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db
from sqlalchemy import text

def add_missing_columns():
    """Add missing columns to communications table"""
    
    with app.app_context():
        try:
            # List of columns to add with their definitions
            columns_to_add = [
                ('status', "VARCHAR(50) DEFAULT 'active'"),
                ('notification_sent', "BOOLEAN DEFAULT False"),
                ('sound_enabled', "BOOLEAN DEFAULT True"),
                ('agora_channel', "VARCHAR(255)"),
                ('recording_url', "VARCHAR(500)"),
                ('start_time', "TIMESTAMP"),
                ('end_time', "TIMESTAMP"),
            ]
            
            print("Checking and adding missing columns to communications table...")
            
            for column_name, column_def in columns_to_add:
                try:
                    # Check if column exists
                    result = db.session.execute(
                        text(f"""
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name = 'communications' AND column_name = '{column_name}'
                        """)
                    ).fetchone()
                    
                    if result:
                        print(f"  ✓ Column '{column_name}' already exists")
                    else:
                        # Add the column
                        alter_query = f"ALTER TABLE communications ADD COLUMN {column_name} {column_def};"
                        db.session.execute(text(alter_query))
                        db.session.commit()
                        print(f"  ✓ Added column '{column_name}'")
                        
                except Exception as e:
                    print(f"  ✗ Error with column '{column_name}': {str(e)}")
                    db.session.rollback()
            
            print("\nMigration completed successfully!")
            
        except Exception as e:
            print(f"Error during migration: {str(e)}")
            sys.exit(1)

if __name__ == '__main__':
    add_missing_columns()
