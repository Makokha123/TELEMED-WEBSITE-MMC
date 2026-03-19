# render_entry.py
import eventlet
eventlet.monkey_patch()

from app import app, socketio, db
from models import User, Patient, Doctor

if __name__ == '__main__':
    # Tables and seed users are handled by app.py's initialize_database()
    # which runs automatically on import (unless SKIP_DB_INIT=1).
    # No need to duplicate seeding logic here.

    # Run the app
    socketio.run(app, host='0.0.0.0', port=10000, debug=False)