import sys
sys.stdout.reconfigure(encoding='utf-8')
from app import app, db
from sqlalchemy import inspect as sqlinspect

with app.app_context():
    inspector = sqlinspect(db.engine)
    tables = inspector.get_table_names()
    if 'consultation_rooms' in tables:
        print('OK: consultation_rooms table EXISTS')
        cols = inspector.get_columns('consultation_rooms')
        for c in cols:
            print(' -', c['name'])
    else:
        print('MISSING: consultation_rooms table NOT FOUND')
        # Create it now
        from models import ConsultationRoom
        db.create_all()
        tables2 = inspector.get_table_names()
        if 'consultation_rooms' in tables2:
            print('CREATED via db.create_all()')
        else:
            print('FAILED to create via db.create_all()')
