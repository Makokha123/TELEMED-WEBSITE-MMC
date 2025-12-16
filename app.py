import eventlet
eventlet.monkey_patch()
print("✓ Eventlet monkey-patched")

import os
import time
import logging
from flask_socketio import SocketIO, emit, join_room, leave_room
import gc
from flask import Flask, g, render_template, request, jsonify, redirect, url_for, flash, session
from flask import send_file, abort
from datetime import datetime, timedelta, timezone, date

import urllib
import math

def timeago(dt):
    if not dt:
        return "N/A"
    now = datetime.now(timezone.utc)
    diff = now - dt if now > dt else dt - now
    seconds = diff.total_seconds()
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes ago"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours ago"
    elif seconds < 604800:
        return f"{int(seconds // 86400)} days ago"
    else:
        return dt.strftime('%b %d, %Y')


from authlib.integrations.flask_client import OAuth

app = Flask(__name__)


preferred_async = 'eventlet'
debug_mode = os.getenv('ENVIRONMENT', '') == 'development' or os.getenv('FLASK_DEBUG', '') == '1'
detected_async = 'eventlet'
print("✓ Eventlet async mode selected")

# Allow CORS origins to be configured via env var (comma-separated), default to '*'
cors_origins = os.getenv('SOCKETIO_CORS_ALLOWED_ORIGINS', '*')
if cors_origins and cors_origins.strip() != '*':
    cors_origins = [o.strip() for o in cors_origins.split(',') if o.strip()]

socketio = SocketIO(
    app,
    cors_allowed_origins=cors_origins,
    async_mode=detected_async,
    logger=debug_mode,
    engineio_logger=debug_mode,
    ping_timeout=int(os.getenv('SOCKETIO_PING_TIMEOUT', 60)),
    ping_interval=int(os.getenv('SOCKETIO_PING_INTERVAL', 25)),
    max_http_buffer_size=int(float(os.getenv('SOCKETIO_MAX_HTTP_BUFFER_SIZE', 1e8))),
    manage_session=False,
    message_queue=os.getenv('REDIS_URL') or os.getenv('CELERY_BROKER_URL') or None,
)

print(f"✓ Socket.IO initialized (async_mode={detected_async}, debug={debug_mode})")

# Define SOCKETIO_AVAILABLE to indicate if socketio is available
SOCKETIO_AVAILABLE = True

# Now import Flask-Dance after app is created
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import aliased, joinedload
from sqlalchemy import QueuePool, func, distinct
from sqlalchemy import event as sqlalchemy_event
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.utils import secure_filename
from uuid import uuid4
from io import BytesIO
from flask import send_file, abort
from PIL import Image
import secrets
import string
import json
import hmac
import hashlib
from flask_migrate import Migrate
import psutil
from sqlalchemy import inspect, text

# Load environment from .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Import models (after attempting to load .env so ENCRYPTION_KEY can be read)
from models import (
    CallSession, Communication, PatientVital, Payment, Prescription, Report,
    PrescriptionAudit, Notification, HealthTip,
    SocialAccount, db, User, Patient, Doctor, Appointment, AuditLog, 
    Testimonial, MedicalRecord, _hash_value, encrypt_file_bytes, decrypt_file_bytes,
    CallHistory, Conversation, Message, Attachment, CallQualityMetrics, UserPresence
    , PushSubscription
)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from config import Config
from pywebpush import webpush, WebPushException
import json as _json
import base64 as _base64
from pathlib import Path

# Initialize serializer for password reset tokens
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production-12345'))

# Global dictionary to track online users for Socket.IO presence
user_sockets = {}
user_last_seen = {}
active_calls = {}
call_rooms = {}  # Track call rooms: {call_id: {'caller': user_id, 'callee': user_id, 'appointment_id': apt_id}}
incoming_call_notifications = {}  # Track incoming calls waiting for answer: {user_id: call_info}
# Push subscriptions (in-memory). Persisted to `push_subscriptions.json` file in app root (best-effort)
push_subscriptions = {}
_PUSH_SUB_FILE = Path(app.root_path) / 'push_subscriptions.json'
# Simple in-memory rate limiter for messages: {user_id: [timestamp,...]}
message_rate = {}


def configure_app():
    """Configure Flask application with environment variables"""
    # Security
    app.config['ASYNC_MODE'] = os.getenv('ASYNC_MODE', 'eventlet')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production-12345')
    app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_UPLOAD_SIZE', 5 * 1024 * 1024))
    
    # Database configuration with URL decoding
    database_url = os.getenv("DATABASE_URL")
    
    # Fix for Neon/Heroku: Decode URL-encoded characters in database name
    if database_url.startswith('postgresql://') or database_url.startswith('postgres://'):
        parsed_url = urllib.parse.urlparse(database_url)
        decoded_path = urllib.parse.unquote(parsed_url.path)
        database_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            decoded_path,
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment
        ))
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 10,  # Reduced for better compatibility
        'max_overflow': 20,
        'poolclass': QueuePool,  # Use the imported class, not a string
        'echo': False
    }
    
    # Email configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
    
    # OAuth configuration
    app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
    app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')
    app.config['FACEBOOK_OAUTH_CLIENT_ID'] = os.getenv('FACEBOOK_OAUTH_CLIENT_ID')
    app.config['FACEBOOK_OAUTH_CLIENT_SECRET'] = os.getenv('FACEBOOK_OAUTH_CLIENT_SECRET')
    
    # File uploads
    app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
    app.config['ENCRYPTION_KEY'] = os.getenv('ENCRYPTION_KEY', 'dev-encryption-key-32-chars-long!123456')
    
    # Payment providers
    app.config['STRIPE_SECRET_KEY'] = os.getenv('STRIPE_SECRET_KEY')
    app.config['STRIPE_WEBHOOK_SECRET'] = os.getenv('STRIPE_WEBHOOK_SECRET')

    # Payment webhook and idempotency settings
    # PAYMENT_PROVIDER_SECRETS should be a JSON object string, e.g. {"mpesa":"secret","stripe":"whsec_xxx"}
    try:
        _pp = os.getenv('PAYMENT_PROVIDER_SECRETS')
        app.config['PAYMENT_PROVIDER_SECRETS'] = json.loads(_pp) if _pp else {}
    except Exception:
        app.config['PAYMENT_PROVIDER_SECRETS'] = {}
    # WEBHOOK_IP_ALLOWLIST should be comma-separated CIDRs e.g. "3.18.12.63/32, 3.130.192.231/32"
    _ip_allow = os.getenv('WEBHOOK_IP_ALLOWLIST')
    app.config['WEBHOOK_IP_ALLOWLIST'] = [p.strip() for p in _ip_allow.split(',')] if _ip_allow else []
    try:
        app.config['IDEMPOTENCY_TTL_DAYS'] = int(os.getenv('IDEMPOTENCY_TTL_DAYS', '7'))
    except Exception:
        app.config['IDEMPOTENCY_TTL_DAYS'] = 7
    
    # Logging
    app.config['LOG_LEVEL'] = os.getenv('LOG_LEVEL', 'INFO')

    # Session / cookie security defaults
    # Use secure cookies only in production (allow local dev over HTTP otherwise)
    is_production = os.getenv('ENVIRONMENT', '').lower() == 'production'
    app.config.setdefault('SESSION_COOKIE_SECURE', is_production)
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
    app.config.setdefault('REMEMBER_COOKIE_SECURE', is_production)
    app.config.setdefault('REMEMBER_COOKIE_HTTPONLY', True)
    app.config.setdefault('PREFERRED_URL_SCHEME', 'https')

    # ICE / TURN configuration with rotation support
    # Env: TURN_URLS (comma list), TURN_TLS=true, ICE_CRED_PROVIDER="static"|"env_rotate"
    # For prod, set TURN over TLS and rotate creds via external mechanism.
    ice_servers = []
    # Always include a STUN but do not rely on it in production
    ice_servers.append({ 'urls': 'stun:stun.l.google.com:19302' })

    turn_urls = [u.strip() for u in (os.getenv('TURN_URLS') or os.getenv('TURN_URL','')).split(',') if u.strip()]
    turn_user = os.getenv('TURN_USER')
    turn_pass = os.getenv('TURN_PASS')
    for url in turn_urls:
        entry = { 'urls': url }
        if turn_user and turn_pass:
            entry['username'] = turn_user
            entry['credential'] = turn_pass
        ice_servers.append(entry)

    app.config['ICE_SERVERS'] = ice_servers
    app.config['ICE_CRED_ROTATE_SECONDS'] = int(os.getenv('ICE_CRED_ROTATE_SECONDS', '3600'))

configure_app()

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
oauth = OAuth(app)


# Security headers to harden responses
@app.after_request
def set_security_headers(response):
    try:
        # Prevent clickjacking
        response.headers.setdefault('X-Frame-Options', 'DENY')
        # Prevent MIME type sniffing
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        # Basic Referrer policy
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        # HSTS - enforce HTTPS for 1 week (adjust in production)
        response.headers.setdefault('Strict-Transport-Security', 'max-age=604800; includeSubDomains')

        env_policy = os.getenv('PERMISSIONS_POLICY')
        if env_policy:
            response.headers.setdefault('Permissions-Policy', env_policy)
        else:
            try:
                # Allow camera/microphone on call/communication pages (same-origin only)
                path = request.path or ''
                allow_camera_mic = False
                # Paths that typically need media access. Use substring checks so
                # routes like '/patient/communication' are covered.
                if ('communication' in path) or path.startswith('/video') or '/call' in path:
                    allow_camera_mic = True
                if allow_camera_mic:
                    # Allow camera, microphone and geolocation for call/communication pages (same-origin)
                    response.headers.setdefault('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(self)')
                else:
                    # Deny by default
                    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            except Exception:
                # On any error, be conservative and deny media access
                response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    except Exception:
        pass
    return response

# ============================================
# DATABASE INITIALIZATION
# ============================================
def create_default_users():
    """Create default admin, doctor, and patient accounts if they don't exist"""
    with app.app_context():
        # Default admin
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_user = User(
                username='admin',
                email='admin@makokha.com',
                role='admin',
                is_active=True
            )
            admin_user.set_password('Admin@123456')
            admin_user.first_name = 'System'
            admin_user.last_name = 'Administrator'
            admin_user.phone = '+254700000000'
            db.session.add(admin_user)
            print("✓ Default admin account created")
        else:
            print("✓ Default admin already exists")
        
        # Default doctor
        doctor_user = User.query.filter_by(username='dr_mwangi').first()
        if not doctor_user:
            doctor_user = User(
                username='dr_mwangi',
                email='dr.mwangi@makokha.com',
                role='doctor',
                is_active=True
            )
            doctor_user.set_password('Doctor@123456')
            doctor_user.first_name = 'David'
            doctor_user.last_name = 'Mwangi'
            doctor_user.phone = '+254700000001'
            db.session.add(doctor_user)
            db.session.commit()
            
            doctor_profile = Doctor(
                user_id=doctor_user.id,
                specialization='General Practitioner',
                license_number='KMC/2020/001',
                experience_years=8,
                consultation_fee=1500.00,
                qualifications='MBChB, MMed',
                availability=True
            )
            db.session.add(doctor_profile)
            print("✓ Default doctor account created")
        else:
            print("✓ Default doctor already exists")
        
        # Default patient
        patient_user = User.query.filter_by(username='patient').first()
        if not patient_user:
            patient_user = User(
                username='patient',
                email='patient@makokha.com',
                role='patient',
                is_active=True
            )
            patient_user.set_password('Patient@123456')
            patient_user.first_name = 'John'
            patient_user.last_name = 'Doe'
            patient_user.phone = '+254711000000'
            db.session.add(patient_user)
            db.session.commit()
            
            patient_profile = Patient(
                user_id=patient_user.id,
                blood_type='O+',
                emergency_contact='Jane Doe +254722000000',
                insurance_provider='NHIF'
            )
            db.session.add(patient_profile)
            print("✓ Default patient account created")
        else:
            print("✓ Default patient already exists")
        
        try:
            db.session.commit()
            print("✓ Default users setup completed")
        except Exception as e:
            db.session.rollback()
            print(f"✗ Error creating default users: {e}")

def initialize_database():
    """Initialize database tables and create default users"""
    with app.app_context():
        try:
            # Create all tables if they don't exist
            db.create_all()
            print("✓ Database tables verified/created")

            # Ensure notifications table has expected columns (hotfix for missing migrations)
            try:
                insp = inspect(db.engine)
                if 'notifications' in insp.get_table_names():
                    cols = [c['name'] for c in insp.get_columns('notifications')]
                    if 'call_status' not in cols:
                        try:
                            with db.engine.begin() as conn:
                                conn.execute(text("ALTER TABLE notifications ADD COLUMN call_status VARCHAR(50)"))
                            print('✓ Added missing column notifications.call_status')
                        except Exception as e:
                            print('✗ Failed to add notifications.call_status:', e)
            except Exception as e:
                print('✗ Failed to inspect notifications table:', e)

            # Ensure users table has call permission columns (hotfix for missing migrations)
            try:
                if 'users' in insp.get_table_names():
                    user_cols = [c['name'] for c in insp.get_columns('users')]
                    needed = {
                        'call_permissions_granted': 'BOOLEAN DEFAULT FALSE',
                        'call_permissions_granted_at': 'TIMESTAMP',
                        'last_known_lat': 'DOUBLE PRECISION',
                        'last_known_lng': 'DOUBLE PRECISION',
                        'last_known_timezone': 'VARCHAR(64)'
                    }
                    for col, coltype in needed.items():
                        if col not in user_cols:
                            try:
                                with db.engine.begin() as conn:
                                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {coltype}"))
                                print(f'✓ Added missing column users.{col}')
                            except Exception as e:
                                print(f'✗ Failed to add users.{col}:', e)
            except Exception as e:
                print('✗ Failed to inspect users table:', e)
            
            # Create default users
            create_default_users()
            
        except Exception as e:
            print(f"✗ Database initialization error: {e}")
            import traceback
            traceback.print_exc()

# Run database initialization unless explicitly skipped (useful for quick dev tests)
if os.getenv('SKIP_DB_INIT', '0') != '1':
    initialize_database()

def safe_display_name(user):
    try:
        first = getattr(user, 'first_name', None)
        last = getattr(user, 'last_name', None)
        if first or last:
            return f"{first or ''} {last or ''}".strip()
        return getattr(user, 'username', 'User')
    except Exception:
        return getattr(user, 'username', 'User')


def safe_username(user_or_name):
    try:
        name = user_or_name.username if hasattr(user_or_name, 'username') else str(user_or_name)
        name = name or f'user_{getattr(user_or_name, "id", "unknown")}'
        return secure_filename(name)
    except Exception:
        return f'user_{getattr(user_or_name, "id", "unknown")}'


# ----------------------
# Socket.IO call handlers
# ----------------------
from flask import copy_current_request_context

def find_active_call(call_id=None, appointment_id=None):
    """
    Helper to find an active call by call_id or appointment_id.
    Returns (key, call_info) where key is the dict key in active_calls.
    """
    if call_id:
        if call_id in active_calls:
            return call_id, active_calls[call_id]
    if appointment_id:
        if appointment_id in active_calls:
            return appointment_id, active_calls[appointment_id]
    # fallback: search by values
    for k, v in active_calls.items():
        if call_id and v.get('id') == call_id:
            return k, v
        if appointment_id and v.get('appointment_id') == appointment_id:
            return k, v
    return None, None

@socketio.on('register_user')
def handle_register_user(data):
    """Register a connected socket for a user: {user_id} """
    try:
        uid = int(data.get('user_id'))
    except Exception:
        return
    sid = request.sid
    # allow multiple sockets per user
    lst = user_sockets.get(uid) or []
    if sid not in lst:
        lst.append(sid)
    user_sockets[uid] = lst
    user_last_seen[uid] = datetime.now(timezone.utc)
    # join a personal room
    join_room(f'user_{uid}')
    emit('registered', {'status': 'ok'})




def _emit_to_user(user_id, event, payload):
    # emit to personal room
    try:
        socketio.emit(event, payload, room=f'user_{user_id}')
    except Exception:
        pass


# SQLAlchemy event listener: when a Notification row is inserted, emit a Socket.IO 'notification' event
def _on_notification_insert(mapper, connection, target):
    try:
        payload = {
            'id': target.id,
            'type': target.notification_type,
            'title': target.title,
            'body': target.body,
            'sender_id': target.sender_id,
            'appointment_id': target.appointment_id,
            'is_read': target.is_read,
            'created_at': target.created_at.isoformat() if getattr(target, 'created_at', None) else None
        }
        # Emit to the user's personal room so connected browsers get the notification in real-time
        try:
            socketio.emit('notification', payload, room=f'user_{target.user_id}')
            # Also emit an unread_count event so clients can update badge cheaply
            try:
                unread = Notification.query.filter_by(user_id=target.user_id, is_read=False).count()
                socketio.emit('unread_count', {'unread_count': unread}, room=f'user_{target.user_id}')
            except Exception:
                # best-effort: if counting fails, ignore
                pass
        except Exception:
            pass
    except Exception:
        pass

# Register the listener
try:
    sqlalchemy_event.listen(Notification, 'after_insert', _on_notification_insert)
except Exception:
    # If Notification isn't available yet or registration fails, ignore gracefully
    pass


# -------------------------
# Web Push helpers and endpoints
# -------------------------
def _load_push_subscriptions():
    try:
        if _PUSH_SUB_FILE.exists():
            with _PUSH_SUB_FILE.open('r', encoding='utf-8') as fh:
                data = _json.load(fh)
                if isinstance(data, dict):
                    push_subscriptions.clear()
                    for k, v in data.items():
                        push_subscriptions[int(k)] = v
    except Exception:
        pass

def _save_push_subscriptions():
    try:
        # persist mapping of user_id -> [subscription,...]
        dump = {str(k): v for k, v in push_subscriptions.items()}
        with _PUSH_SUB_FILE.open('w', encoding='utf-8') as fh:
            _json.dump(dump, fh)
    except Exception:
        pass

# Load existing subscriptions at startup (best-effort)
try:
    _load_push_subscriptions()
except Exception:
    pass


@app.route('/api/ice', methods=['GET'])
@login_required
def get_ice():
    """Return current ICE server config without hard-coding secrets in clients.
    In production, implement rotation for TURN creds and fetch here.
    """
    # Basic ETag to help cache for a short time but rotate if env changes
    try:
        from hashlib import sha256
        key = sha256((os.getenv('TURN_USER','') + '|' + os.getenv('TURN_URLS','') + '|' + os.getenv('TURN_PASS','')).encode()).hexdigest()
    except Exception:
        key = None
    resp = jsonify({'iceServers': app.config.get('ICE_SERVERS', [])})
    if key:
        resp.headers['ETag'] = key
    resp.headers['Cache-Control'] = 'private, max-age=120'
    return resp

@app.route('/api/push/vapid_public_key', methods=['GET'])
def vapid_public_key():
    """Return VAPID public key (base64url) for client subscription.
    The server must be configured with VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY environment variables.
    """
    pub = os.getenv('VAPID_PUBLIC_KEY')
    if not pub:
        return jsonify({'success': False, 'error': 'VAPID keys not configured on server'}), 500
    return jsonify({'success': True, 'vapid_public_key': pub})


@app.route('/api/push/subscribe', methods=['POST'])
def push_subscribe():
    try:
        payload = request.get_json(force=True)
    except Exception:
        payload = None
    if not payload:
        return jsonify({'success': False, 'error': 'invalid_payload'}), 400
    subscription = payload.get('subscription') or payload.get('sub')
    # prefer logged in user if available
    uid = None
    try:
        if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            uid = int(getattr(current_user, 'id'))
    except Exception:
        uid = None
    if not uid:
        # fallback to supplied user_id
        try:
            uid = int(payload.get('user_id'))
        except Exception:
            return jsonify({'success': False, 'error': 'missing_user_id'}), 400
    if not subscription or not isinstance(subscription, dict):
        return jsonify({'success': False, 'error': 'invalid_subscription'}), 400

    # Persist to DB when available
    try:
        if 'db' in globals():
            # Upsert by endpoint
            ep = subscription.get('endpoint')
            existing = None
            try:
                existing = PushSubscription.query.filter_by(endpoint=ep).first() if ep else None
            except Exception:
                existing = None
            if existing:
                existing.keys = subscription.get('keys') or subscription.get('keys', {})
                existing.raw = subscription
                existing.is_active = True
                try:
                    existing.user_agent = request.headers.get('User-Agent')
                except Exception:
                    pass
                db.session.add(existing)
                db.session.commit()
            else:
                try:
                    ps = PushSubscription(user_id=uid, endpoint=ep or '', keys=subscription.get('keys') or {}, raw=subscription, user_agent=request.headers.get('User-Agent'))
                    db.session.add(ps)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
    except Exception:
        pass

    # Keep file-backed store as best-effort cache as well
    lst = push_subscriptions.get(uid) or []
    endpoint = subscription.get('endpoint')
    if not any(s.get('endpoint') == endpoint for s in lst):
        lst.append(subscription)
    push_subscriptions[uid] = lst
    _save_push_subscriptions()
    return jsonify({'success': True})


@app.route('/api/push/unsubscribe', methods=['POST'])
def push_unsubscribe():
    try:
        payload = request.get_json(force=True)
    except Exception:
        payload = None
    if not payload:
        return jsonify({'success': False, 'error': 'invalid_payload'}), 400
    subscription = payload.get('subscription') or payload.get('sub')
    uid = None
    try:
        if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            uid = int(getattr(current_user, 'id'))
    except Exception:
        uid = None
    if not uid:
        try:
            uid = int(payload.get('user_id'))
        except Exception:
            return jsonify({'success': False, 'error': 'missing_user_id'}), 400
    if not subscription:
        return jsonify({'success': False, 'error': 'invalid_subscription'}), 400
    # Remove from DB when available
    try:
        if 'db' in globals():
            ep = subscription.get('endpoint')
            try:
                PushSubscription.query.filter_by(endpoint=ep).delete()
                db.session.commit()
            except Exception:
                db.session.rollback()
    except Exception:
        pass

    # Remove from file-backed store as well
    lst = push_subscriptions.get(uid) or []
    endpoint = subscription.get('endpoint')
    lst = [s for s in lst if s.get('endpoint') != endpoint]
    if lst:
        push_subscriptions[uid] = lst
    else:
        push_subscriptions.pop(uid, None)
    _save_push_subscriptions()
    return jsonify({'success': True})


def _send_push_to_subscription(subscription, payload):
    """Send a push message using pywebpush. Returns True on success, False otherwise."""
    vapid_private = os.getenv('VAPID_PRIVATE_KEY')
    vapid_email = os.getenv('VAPID_CLAIMS_SUB', 'mailto:admin@makokhamedical.com')
    if not vapid_private:
        raise RuntimeError('VAPID_PRIVATE_KEY not set')
    try:
        webpush(
            subscription_info=subscription,
            data=_json.dumps(payload),
            vapid_private_key=vapid_private,
            vapid_claims={"sub": vapid_email}
        )
        return True
    except WebPushException as ex:
        # If subscription is no longer valid, caller should remove it
        app.logger.warning('WebPush failed: %s', str(ex))
        return False
    except Exception as e:
        app.logger.exception('Unexpected error sending webpush: %s', e)
        return False


@app.route('/api/push/send', methods=['POST'])
def push_send():
    """Send a push notification to a user or test payload.
    JSON body: { user_id: <int>, payload: { title, body, url, ... } }
    If user_id omitted and current user is provided or request contains 'to_all': send accordingly.
    """
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}
    target_user = data.get('user_id')
    payload = data.get('payload') or {'title': data.get('title', 'Notification'), 'body': data.get('body', ''), 'url': data.get('url', '/')}
    if not target_user:
        # allow sending to current user for testing
        try:
            if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
                target_user = int(getattr(current_user, 'id'))
        except Exception:
            target_user = None
    if not target_user:
        return jsonify({'success': False, 'error': 'missing_user_id'}), 400

    # Prefer DB-backed subscriptions if model exists
    subs = []
    try:
        if 'PushSubscription' in globals():
            subs_q = PushSubscription.query.filter_by(user_id=int(target_user), is_active=True).all()
            subs = [s.raw for s in subs_q if getattr(s, 'raw', None)]
    except Exception:
        subs = push_subscriptions.get(int(target_user)) or []
    successes = 0
    to_remove = []
    for s in list(subs):
        ok = _send_push_to_subscription(s, payload)
        if ok:
            successes += 1
        else:
            # schedule to remove invalid subscription
            if s.get('endpoint'):
                to_remove.append(s.get('endpoint'))
    if to_remove:
        subs = [x for x in subs if x.get('endpoint') not in to_remove]
        if subs:
            push_subscriptions[int(target_user)] = subs
        else:
            push_subscriptions.pop(int(target_user), None)
        _save_push_subscriptions()

    return jsonify({'success': True, 'sent': successes})



@socketio.on('initiate_video_call')
def handle_initiate_video_call(data):
    """Caller requests to start a video call. data: {caller_id, callee_id, appointment_id}
    Server creates a call_id, stores active_calls, notifies callee with incoming_video_call."""
    try:
        caller_id = int(data.get('caller_id'))
        callee_id = int(data.get('callee_id'))
        appointment_id = int(data.get('appointment_id')) if data.get('appointment_id') else None
    except Exception:
        emit('call_error', {'message': 'invalid_parameters'})
        return

    call_id = str(uuid4())
    call_info = {
        'id': call_id,
        'caller': caller_id,
        'callee': callee_id,
        'appointment_id': appointment_id,
        'started_at': datetime.now(timezone.utc).isoformat(),
        'status': 'ringing',
        'call_type': 'video'
    }

    # Enrich call info with user display names and profile pictures when available
    try:
        caller_user = db.session.get(User, caller_id)
        callee_user = db.session.get(User, callee_id)
        if caller_user:
            call_info['caller_name'] = safe_display_name(caller_user)
            # Provide a full URL that the client can use to load the profile picture
            try:
                call_info['caller_profile_picture'] = get_user_profile_picture_url(caller_user)
            except Exception:
                call_info['caller_profile_picture'] = None
        if callee_user:
            call_info['callee_name'] = safe_display_name(callee_user)
            try:
                call_info['callee_profile_picture'] = get_user_profile_picture_url(callee_user)
            except Exception:
                call_info['callee_profile_picture'] = None
    except Exception:
        pass

    # Check if callee is on another call (busy)
    is_busy = any(c['callee'] == callee_id and c['status'] in ['ringing', 'ongoing'] 
                  for c in active_calls.values() if c.get('id') != call_id)
    
    if is_busy:
        # Notify caller that callee is busy
        busy_notification = {
            'call_id': call_id,
            'status': 'busy',
            'message': f'{call_info.get("callee_name", "User")} is currently on another call',
            'callee_name': call_info.get('callee_name', 'User'),
            'recommendation': 'Please wait or end this attempt'
        }
        _emit_to_user(caller_id, 'call_failed_busy', busy_notification)
        
        # Create notification for caller
        try:
            notif = Notification(
                user_id=caller_id,
                appointment_id=appointment_id,
                notification_type='busy_video_call',
                sender_id=callee_id,
                title='User Busy',
                body=f'{call_info.get("callee_name", "User")} is currently on another call',
                call_status='busy'
            )
            db.session.add(notif)
            db.session.commit()
        except Exception:
            db.session.rollback()
        return

    # Check if callee is online (connected via socket)
    callee_is_online = callee_id in user_sockets and bool(user_sockets[callee_id])
    
    # Store call info
    active_calls[call_id] = call_info
    # Also store by appointment_id when available for compatibility with other handlers
    if appointment_id:
        try:
            active_calls[appointment_id] = call_info
        except Exception:
            pass
    incoming_call_notifications[callee_id] = call_info

    # update appointment status if present
    if appointment_id:
        try:
            apt = db.session.get(Appointment, appointment_id)
            if apt:
                apt.call_status = 'ringing'
                apt.call_initiated_by = caller_id
                db.session.commit()
        except Exception:
            db.session.rollback()

    if callee_is_online:
        # Callee is online - send incoming call notification
        _emit_to_user(callee_id, 'incoming_video_call', call_info)
        _emit_to_user(caller_id, 'outgoing_video_call_started', call_info)
        
        # Set timeout for missed call (60 seconds)
        def video_call_timeout():
            try:
                with app.app_context():
                    key, current = find_active_call(call_id=call_id, appointment_id=appointment_id)
                    if current and current.get('status') == 'ringing':
                        # update stored status
                        if key in active_calls:
                            active_calls[key]['status'] = 'unanswered'
                        incoming_call_notifications.pop(callee_id, None)

                        # Update appointment to missed
                        try:
                            if appointment_id:
                                apt = db.session.get(Appointment, appointment_id)
                                if apt:
                                    apt.call_status = 'missed'
                                    db.session.commit()
                        except Exception:
                            db.session.rollback()

                        # Notify caller of missed call
                        _emit_to_user(caller_id, 'video_call_unanswered', {
                            'call_id': current.get('id') if current else call_id,
                            'appointment_id': current.get('appointment_id') if current else appointment_id,
                            'message': f'{call_info.get("callee_name", "User")} did not answer',
                            'status': 'unanswered'
                        })

                        # Create missed call notification for callee
                        try:
                            notif = Notification(
                                user_id=callee_id,
                                appointment_id=appointment_id,
                                notification_type='missed_video_call',
                                sender_id=caller_id,
                                title='Missed Video Call',
                                body=f'{call_info.get("caller_name", "User")} called you',
                                call_status='missed'
                            )
                            db.session.add(notif)
                            db.session.commit()
                        except Exception:
                            db.session.rollback()

                        # Clean up
                        if key:
                            active_calls.pop(key, None)
            except Exception:
                # don't let background task crash
                pass
        
        socketio.start_background_task(lambda: (socketio.sleep(60), video_call_timeout()))
    else:
        # Callee is offline but might be accessible via web/browser
        offline_notification = {
            'call_id': call_id,
            'status': 'offline_attempting',
            'message': f'{call_info.get("callee_name", "User")} is currently offline',
            'callee_name': call_info.get('callee_name', 'User'),
            'recommendation': 'Attempting to reach via web/browser...'
        }
        _emit_to_user(caller_id, 'outgoing_video_call_started', offline_notification)
        
        # Still allow the call to go through and wait for a response
        # with extended timeout for offline users
        def video_call_offline_timeout():
            try:
                with app.app_context():
                    key, current = find_active_call(call_id=call_id, appointment_id=appointment_id)
                    if current and current.get('status') == 'ringing':
                        if key in active_calls:
                            active_calls[key]['status'] = 'connection_failed'
                        incoming_call_notifications.pop(callee_id, None)

                        # Update appointment to missed
                        try:
                            if appointment_id:
                                apt = db.session.get(Appointment, appointment_id)
                                if apt:
                                    apt.call_status = 'missed'
                                    db.session.commit()
                        except Exception:
                            db.session.rollback()

                        # Notify caller of connection failure
                        _emit_to_user(caller_id, 'video_call_connection_failed', {
                            'call_id': current.get('id') if current else call_id,
                            'appointment_id': current.get('appointment_id') if current else appointment_id,
                            'message': f'Unable to connect to {call_info.get("callee_name", "User")}',
                            'status': 'connection_failed'
                        })

                        # Create connection failed notification for caller
                        try:
                            notif = Notification(
                                user_id=caller_id,
                                appointment_id=appointment_id,
                                notification_type='video_call_failed',
                                sender_id=callee_id,
                                title='Call Connection Failed',
                                body=f'Unable to reach {call_info.get("callee_name", "User")}',
                                call_status='connection_failed'
                            )
                            db.session.add(notif)
                            db.session.commit()
                        except Exception:
                            db.session.rollback()

                        # Clean up
                        if key:
                            active_calls.pop(key, None)
            except Exception:
                # background safety: ignore
                pass
        
        # Extended timeout for offline users (90 seconds)
        socketio.start_background_task(lambda: (socketio.sleep(90), video_call_offline_timeout()))


@socketio.on('accept_video_call')
def handle_accept_video_call(data):
    # data: {call_id, user_id}
    call_id = data.get('call_id')
    appointment_id = data.get('appointment_id') or data.get('apt')
    user_id = data.get('user_id')
    key, info = find_active_call(call_id=call_id, appointment_id=appointment_id)
    if not info:
        app.logger.warning('accept_video_call: call not found (call_id=%s appointment_id=%s)', call_id, appointment_id)
        emit('call_error', {'message': 'call_not_found'})
        return
    
    # Check if caller has another active call (call collision)
    has_active_call = any(c['caller'] == info['caller'] and c.get('status') == 'ongoing'
                         for c in active_calls.values() if c.get('id') != info.get('id'))
    
    if has_active_call:
        # Reject if caller is busy too
        emit('call_error', {'message': 'caller_has_active_call'})
        return
    
    # mark as ongoing
    info['status'] = 'ongoing'
    info['accepted_at'] = datetime.now(timezone.utc).isoformat()
    # create CallSession row
    try:
        cs = CallSession(appointment_id=info.get('appointment_id') or None, participants=[info['caller'], info['callee']])
        db.session.add(cs)
        db.session.commit()
        info['call_session_id'] = cs.id
    except Exception:
        db.session.rollback()

    # Remove from missed call tracking
    incoming_call_notifications.pop(info.get('callee'), None)
    
    # Update appointment status
    try:
        if info.get('appointment_id'):
            apt = db.session.get(Appointment, info.get('appointment_id'))
            if apt:
                apt.call_status = 'ongoing'
                db.session.commit()
    except Exception:
        db.session.rollback()

    # notify both users
    _emit_to_user(info['caller'], 'call_accepted', info)
    _emit_to_user(info['callee'], 'call_accepted', info)


@socketio.on('reject_video_call')
def handle_reject_video_call(data):
    call_id = data.get('call_id')
    appointment_id = data.get('appointment_id') or data.get('apt')
    reason = data.get('reason') or 'rejected'
    key, info = find_active_call(call_id=call_id, appointment_id=appointment_id)
    if key:
        info = active_calls.pop(key, None)
    else:
        info = None
    if info:
        incoming_call_notifications.pop(info.get('callee'), None)
        
        # Create rejection notification for caller
        try:
            rejection_reason = 'Call declined' if reason == 'rejected' else f'Call {reason}'
            notif = Notification(
                user_id=info['caller'],
                appointment_id=info.get('appointment_id'),
                notification_type='video_call_rejected',
                sender_id=info['callee'],
                title='Call Declined',
                body=f'{info.get("callee_name", "User")} declined your video call',
                call_status='rejected'
            )
            db.session.add(notif)
        except Exception:
            pass
        
        # update appointment
        try:
            if info.get('appointment_id'):
                apt = db.session.get(Appointment, info.get('appointment_id'))
                if apt:
                    apt.call_status = 'missed'
                    db.session.commit()
        except Exception:
            db.session.rollback()

        _emit_to_user(info['caller'], 'call_rejected', {'call_id': info.get('id'), 'reason': reason, 'callee_name': info.get('callee_name', 'User'), 'appointment_id': info.get('appointment_id')})
        _emit_to_user(info['callee'], 'call_rejected', {'call_id': info.get('id'), 'reason': reason, 'appointment_id': info.get('appointment_id')})


@socketio.on('end_call')
def handle_end_call(data):
    call_id = data.get('call_id')
    appointment_id = data.get('appointment_id')
    ended_by = data.get('ended_by')
    # Support both call_id and appointment_id keys (clients may send either)
    key, info = find_active_call(call_id=call_id, appointment_id=appointment_id)
    if key:
        info = active_calls.pop(key, None)
    if info:
        incoming_call_notifications.pop(info.get('callee'), None)
        
        # Create call end notification
        other_user_id = info['callee'] if info['caller'] != ended_by else info['caller']
        try:
            notif = Notification(
                user_id=other_user_id,
                appointment_id=info.get('appointment_id'),
                notification_type='video_call_ended',
                sender_id=ended_by,
                title='Video Call Ended',
                body=f'Video call with {info.get("caller_name" if other_user_id == info["callee"] else "callee_name", "User")} has ended',
                call_status='ended'
            )
            db.session.add(notif)
        except Exception:
            pass
        
        # update call session and appointment
        try:
            cs_id = info.get('call_session_id')
            if cs_id:
                cs = db.session.get(CallSession, cs_id)
                if cs and not cs.ended_at:
                    cs.ended_at = datetime.now(timezone.utc)
                    if cs.started_at:
                        try:
                            started = cs.started_at
                            duration = int((datetime.now(timezone.utc) - started).total_seconds())
                            cs.duration = duration
                        except Exception:
                            pass
                    db.session.commit()
        except Exception:
            db.session.rollback()

        # update appointment status and possibly mark completed if doctor ended
        try:
            if info.get('appointment_id'):
                apt = db.session.get(Appointment, info.get('appointment_id'))
                if apt:
                    apt.call_status = 'ended'
                    # if the ended_by is the doctor user, mark appointment completed
                    try:
                        doctor_user_id = None
                        if apt.doctor:
                            doctor_user_id = getattr(apt.doctor, 'user_id', None)
                        if doctor_user_id and ended_by and int(ended_by) == int(doctor_user_id):
                            apt.status = 'completed'
                            # emit testimonial prompt to patient
                            _emit_to_user(apt.patient.user_id, 'prompt_testimonial', {
                                'appointment_id': apt.id,
                                'doctor_id': apt.doctor_id
                            })
                    except Exception:
                        pass
                    db.session.commit()
        except Exception:
            db.session.rollback()

        # notify other participant
        _emit_to_user(info['caller'], 'call_ended', {'call_id': info.get('id'), 'appointment_id': info.get('appointment_id'), 'ended_by': ended_by})
        _emit_to_user(info['callee'], 'call_ended', {'call_id': info.get('id'), 'appointment_id': info.get('appointment_id'), 'ended_by': ended_by})

        # Enrich payload with doctor/user ids so clients can redirect appropriately
        doctor_user_id = None
        patient_user_id = None
        try:
            apt = db.session.get(Appointment, appointment_id)
            if apt:
                doc = db.session.get(Doctor, apt.doctor_id)
                if doc:
                    doctor_user_id = doc.user_id
                pat = db.session.get(Patient, apt.patient_id)
                if pat:
                    patient_user_id = pat.user_id
        except Exception:
            pass

        end_data = {
            'appointment_id': appointment_id,
            'ended_by': current_user.id,
            'reason': data.get('reason', 'ended_by_user'),
            'message': data.get('message', 'Call ended'),
            'doctor_user_id': doctor_user_id,
            'patient_user_id': patient_user_id
        }



def _uploads_rel_root():
    """Return uploads root relative to `static` (e.g. 'uploads')."""
    rel = app.config.get('UPLOAD_FOLDER', 'static/uploads').replace('\\', '/')
    if rel.startswith('static/'):
        return rel[len('static/'):]
    if rel == 'static':
        return ''
    return rel


def resolve_stored_path(stored_path):
    """Resolve stored_path to absolute filesystem path. For external URLs, returns the URL string unchanged."""
    if not stored_path:
        return None
    if isinstance(stored_path, str) and stored_path.startswith('http'):
        return stored_path
    if os.path.isabs(stored_path):
        return stored_path
    # assume relative to app.root_path
    return os.path.join(app.root_path, stored_path)


google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    scope=["profile", "email"],
    # Do not pass `current_user` at import time — use storage without binding a user
    storage=SQLAlchemyStorage(SocialAccount, db.session)
)

facebook_bp = make_facebook_blueprint(
    client_id=app.config['FACEBOOK_OAUTH_CLIENT_ID'],
    client_secret=app.config['FACEBOOK_OAUTH_CLIENT_SECRET'],
    scope=["email", "public_profile"],
    # Do not pass `current_user` at import time — use storage without binding a user
    storage=SQLAlchemyStorage(SocialAccount, db.session)
)

twitter_bp = None

# Register available OAuth blueprints
app.register_blueprint(google_bp, url_prefix="/login")
app.register_blueprint(facebook_bp, url_prefix="/login")

# Register communication blueprint
from api.communication import communication_bp
app.register_blueprint(communication_bp, url_prefix="/api")

# Register versioned API blueprint
try:
    from api.v1 import v1_bp
    app.register_blueprint(v1_bp)
    print("✓ Registered /api/v1 blueprint")
except Exception as e:
    print(f"✗ Failed to register /api/v1 blueprint: {e}")

def cleanup_old_sessions():
    """Clean up old user sessions"""
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
    users_to_remove = []
    
    for user_id, last_seen_str in list(user_last_seen.items()):
        try:
            last_seen = datetime.fromisoformat(last_seen_str)
            if last_seen < cutoff_time:
                users_to_remove.append(user_id)
        except:
            pass
    
    for user_id in users_to_remove:
        if user_id in user_sockets:
            del user_sockets[user_id]
        if user_id in user_last_seen:
            del user_last_seen[user_id]
    
    # Force garbage collection
    gc.collect()

# Schedule cleanup (run every hour)
import threading
def schedule_cleanup():
    while True:
        try:
            # Run the cleanup in an application context so any DB or app resources
            # referenced by cleanup_old_sessions are available.
            with app.app_context():
                app.logger.debug('schedule_cleanup: running cleanup_old_sessions')
                try:
                    cleanup_old_sessions()
                    app.logger.debug('schedule_cleanup: completed cleanup_old_sessions')
                except Exception as e:
                    app.logger.exception('schedule_cleanup: cleanup_old_sessions error: %s', e)
        except Exception as e:
            # Log outer exceptions but keep the loop alive
            try:
                app.logger.exception('schedule_cleanup: unexpected error: %s', e)
            except Exception:
                print(f'schedule_cleanup unexpected error: {e}')
        # Wait 1 hour before next run
        threading.Event().wait(3600)  # Wait 1 hour


# Prescription expiry worker: marks prescriptions expired when expiry_date is reached
def prescription_expiry_worker(interval_seconds=600):
    from time import sleep
    while True:
        try:
            with app.app_context():
                now = datetime.now(timezone.utc)
                expiring = Prescription.query.filter(Prescription.expiry_date != None, Prescription.expiry_date < now, Prescription.is_expired == False).all()
                for p in expiring:
                    p.is_expired = True
                    try:
                        audit = PrescriptionAudit(prescription_id=p.id, user_id=None, action='auto_expired', extra_info='expiry_date passed')
                        db.session.add(audit)
                    except Exception:
                        db.session.rollback()
                if expiring:
                    db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
        sleep(interval_seconds)


def start_background_workers():
    try:
        t = threading.Thread(target=prescription_expiry_worker, kwargs={'interval_seconds':600}, daemon=True, name='prescription_expiry_worker')
        t.start()
        app.logger.info('Started background thread: prescription_expiry_worker')
    except Exception as e:
        try:
            app.logger.exception('Failed to start prescription_expiry_worker: %s', e)
        except Exception:
            print(f'Failed to start prescription_expiry_worker: {e}')

# Start background workers when app initializes (best-effort)
try:
    start_background_workers()
except Exception:
    pass

# Social authentication success handler
@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", category="error")
        return False

    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", category="error")
        return False

    google_info = resp.json()
    google_user_id = google_info["id"]

    # Find this OAuth token in the database, or create it
    query = SocialAccount.query.filter_by(
        provider=blueprint.name,
        provider_user_id=google_user_id,
    )
    try:
        social_account = query.one()
    except NoResultFound:
        social_account = SocialAccount(
            provider=blueprint.name,
            provider_user_id=google_user_id,
            access_token=token["access_token"],
        )

    if social_account.user:
        login_user(social_account.user)
        flash("Successfully signed in with Google.", "success")
    else:
        # Create a new user
        user = User(
            username=google_info["email"].split('@')[0],
            email=google_info["email"],
            first_name=google_info.get("given_name", ""),
            last_name=google_info.get("family_name", ""),
            role='patient'
        )
        # Generate a random password for social login users
        user.set_password(os.urandom(24).hex())
        
        # Create user profile picture from Google
        if google_info.get("picture"):
            user.profile_picture = google_info["picture"]

        # Add the user to the database
        db.session.add(user)
        db.session.commit()

        # Create patient profile for newly signed-up users
        try:
            patient = Patient(user_id=user.id)
            db.session.add(patient)
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Link social account to user
        social_account.user = user
        db.session.add(social_account)
        db.session.commit()

        # Create patient profile
        patient = Patient(user_id=user.id)
        db.session.add(patient)
        db.session.commit()

        # Log in the new user
        login_user(user)
        flash("Successfully signed up with Google!", "success")

    # Disable Flask-Dance's default behavior for saving the OAuth token
    return False

@oauth_authorized.connect_via(facebook_bp)
def facebook_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Facebook.", category="error")
        return False

    resp = blueprint.session.get("/me?fields=id,email,first_name,last_name,picture")
    if not resp.ok:
        flash("Failed to fetch user info from Facebook.", category="error")
        return False

    facebook_info = resp.json()
    facebook_user_id = facebook_info["id"]

    query = SocialAccount.query.filter_by(
        provider=blueprint.name,
        provider_user_id=facebook_user_id,
    )
    try:
        social_account = query.one()
    except NoResultFound:
        social_account = SocialAccount(
            provider=blueprint.name,
            provider_user_id=facebook_user_id,
            access_token=token["access_token"],
        )

    if social_account.user:
        login_user(social_account.user)
        flash("Successfully signed in with Facebook.", "success")
    else:
        # Create username from email or use a generated one
        username = facebook_info.get("email", "").split('@')[0] if facebook_info.get("email") else f"fb_{facebook_user_id}"
        
        user = User(
            username=username,
            email=facebook_info.get("email", f"{facebook_user_id}@facebook.com"),
            first_name=facebook_info.get("first_name", ""),
            last_name=facebook_info.get("last_name", ""),
            role='patient'
        )
        user.set_password(os.urandom(24).hex())
        
        # Add profile picture from Facebook
        if facebook_info.get("picture", {}).get("data", {}).get("url"):
            user.profile_picture = facebook_info["picture"]["data"]["url"]

        db.session.add(user)
        db.session.commit()

        social_account.user = user
        db.session.add(social_account)
        db.session.commit()

        # Create patient profile
        patient = Patient(user_id=user.id)
        db.session.add(patient)
        db.session.commit()

        # Log in the new user
        login_user(user)
        flash("Successfully signed up with Facebook!", "success")

# Twitter OAuth handlers removed.

# Handle OAuth errors
@oauth_error.connect
def auth_error(blueprint, error, error_description=None, error_uri=None):
    msg = f"OAuth error from {blueprint.name}: {error}"
    if error_description:
        msg += f" ({error_description})"
    if error_uri:
        msg += f" ({error_uri})"
    flash(msg, "error")

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

def generate_csrf_token():
    """Generate CSRF token"""
    if hasattr(g, 'csrf_token'):
        return g.csrf_token
    token = generate_csrf()
    g.csrf_token = token
    return token

# Make CSRF token available to all templates
@app.context_processor
def inject_csrf_token():
    """Inject CSRF token into template context"""
    return dict(csrf_token=generate_csrf_token)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def handle_file_upload(user, file_obj, upload_type='profile_pics', encrypt=True):
    """
    Unified secure upload handler with validation, MIME sniffing, UUID storage, and encryption.
    - Validates extension and inspects first bytes for content type
    - Stores outside static/ path where possible, and never serves directly
    - Uses UUID-based filenames; normalizes original name
    - Returns relative path under configured UPLOAD_FOLDER for DB storage
    """
    if not file_obj or not file_obj.filename:
        return None

    # Normalize filename and validate extension
    original = secure_filename(file_obj.filename)
    if not allowed_file(original):
        return None

    # Read a limited buffer for MIME sniffing
    try:
        head = file_obj.stream.read(4096)
        file_obj.stream.seek(0)
    except Exception:
        head = b''

    import mimetypes
    guessed = file_obj.mimetype or mimetypes.guess_type(original)[0] or 'application/octet-stream'

    # Basic server-side content sniffing checks for common types
    def looks_like_image(buf):
        sigs = [b'\xFF\xD8\xFF', b'PNG', b'GIF8', b'RIFF']
        return any(sig in buf[:16] for sig in sigs)
    def looks_like_pdf(buf):
        return buf.startswith(b'%PDF')

    ext = (original.rsplit('.',1)[1].lower() if '.' in original else '')
    if ext in ('jpg','jpeg','png','gif','webp') and not looks_like_image(head):
        return None
    if ext == 'pdf' and not looks_like_pdf(head):
        return None

    try:
        rel_root = _uploads_rel_root() or 'uploads'
        user_role = getattr(user, 'role', 'user')
        user_id = getattr(user, 'id', 'unknown')
        rel_dir = os.path.join(rel_root, user_role, str(user_id), upload_type).replace('\\', '/')
        full_dir = os.path.join(app.root_path, rel_dir)
        os.makedirs(full_dir, exist_ok=True)

        # UUID-based storage; store original as metadata suffix only
        storage_name = f"{uuid4().hex}__{original}"
        if encrypt:
            storage_name += '.enc'

        full_path = os.path.join(full_dir, storage_name)
        rel_path_for_db = os.path.join(rel_dir, storage_name).replace('\\', '/')

        # Stream to disk; encrypt if configured
        raw = file_obj.read()
        if encrypt:
            encrypted_bytes = encrypt_file_bytes(raw)
            if not encrypted_bytes:
                return None
            with open(full_path, 'wb') as fh:
                fh.write(encrypted_bytes)
        else:
            with open(full_path, 'wb') as fh:
                fh.write(raw)

        return rel_path_for_db
    except Exception as e:
        logging.error(f"File upload error for user {getattr(user,'id','unknown')}: {e}")
        return None

# Routes
@app.route('/')
def index():
    # Get real-time statistics from database
    stats = {
        'total_patients': Patient.query.count(),
        'total_doctors': Doctor.query.count(),
        'total_appointments': Appointment.query.count(),
        'satisfaction_rate': 95  # You can calculate this from feedback/reviews if available
    }
    
    # Get available doctors for the doctors section
    doctors = db.session.query(Doctor, User).join(
        User, Doctor.user_id == User.id
    ).filter(Doctor.availability == True).all()
    
    # Get recent public testimonials
    try:
        testimonials = Testimonial.query.filter_by(is_public=True).order_by(Testimonial.created_at.desc()).limit(6).all()
    except Exception:
        testimonials = []
    
    # If user is authenticated, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        else:
            return redirect(url_for('patient_dashboard'))
    
    return render_template('index.html', 
                         stats=stats, 
                         doctors=doctors, 
                         testimonials=testimonials)

# Add this function before creating the app
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    """Convert string to datetime and format it"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return value
    if hasattr(value, 'strftime'):
        return value.strftime(format)
    return value

def to_datetime(value):
    """Convert string to datetime object"""
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return value
    return value

# Register the filters
app.jinja_env.filters['datetimeformat'] = datetimeformat
app.jinja_env.filters['to_datetime'] = to_datetime

# Dedicated About page
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        old_username = current_user.username
        # Handle profile picture upload, username, password, theme, wallpaper, etc.
        # Implement logic for each field as needed
        # Determine requested username and apply early so uploads land in new folder
        requested_username = request.form.get('username')
        if requested_username:
            requested_username = secure_filename(requested_username)
        # Apply username change in-memory first so uploaded files use the new folder
        if requested_username and requested_username != current_user.username:
            current_user.username = requested_username

        # Example: handle profile picture
        profile_picture = request.files.get('profile_picture')
        if profile_picture and profile_picture.filename:
            pic_path = handle_file_upload(current_user, profile_picture, upload_type='profile_pics', encrypt=True)
            if pic_path:
                current_user.profile_picture = pic_path
                flash('Profile picture updated successfully', 'success')
            else:
                flash('Invalid profile picture file type or upload failed.', 'error')
        # Note: username already applied above before handling uploads
        # Example: handle password change
        new_password = request.form.get('new_password')
        if new_password:
            current_user.set_password(new_password)
        # Example: handle theme
        theme = request.form.get('theme')
        if theme:
            current_user.theme = theme
        # Role-specific toggles
        if current_user.role == 'admin':
            allow_user_creation = True if request.form.get('allow_user_creation') else False
            try:
                current_user.allow_user_creation = allow_user_creation
            except Exception:
                pass
        elif current_user.role == 'doctor':
            show_availability = True if request.form.get('show_availability') else False
            try:
                current_user.show_availability = show_availability
            except Exception:
                pass
        else:
            share_data = True if request.form.get('share_data') else False
            try:
                current_user.share_data = share_data
            except Exception:
                pass
        # Example: handle wallpaper (saved under uploads but not encrypted)
        wallpaper = request.files.get('wallpaper')
        if wallpaper and wallpaper.filename:
            filename = secure_filename(wallpaper.filename)
            if allowed_file(filename):
                username_for = safe_username(current_user)
                rel_root = _uploads_rel_root() or 'uploads'
                rel_dir = os.path.join(rel_root, username_for, 'wallpapers').replace('\\', '/')
                full_dir = os.path.join(app.root_path, rel_dir)
                os.makedirs(full_dir, exist_ok=True)
                stored_name = f"{uuid4().hex}__{filename}"
                dest_path = os.path.join(full_dir, stored_name)
                wallpaper.save(dest_path)
                current_user.wallpaper = os.path.join(rel_dir, stored_name).replace('\\', '/')
            else:
                flash('Invalid wallpaper file type.', 'error')
        db.session.commit()

        # If username changed, attempt to migrate existing uploads folder and update paths
        try:
            new_username = current_user.username
            if old_username and new_username and old_username != new_username:
                old_dir = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), old_username)
                new_dir = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), new_username)
                if os.path.exists(old_dir) and not os.path.exists(new_dir):
                    os.makedirs(os.path.dirname(new_dir), exist_ok=True)
                    os.rename(old_dir, new_dir)
                # Update stored paths on the user record that referenced old_username
                updated = False
                if current_user.profile_picture and old_username in current_user.profile_picture:
                    current_user.profile_picture = current_user.profile_picture.replace(old_username, new_username)
                    updated = True
                if getattr(current_user, 'wallpaper', None) and old_username in current_user.wallpaper:
                    current_user.wallpaper = current_user.wallpaper.replace(old_username, new_username)
                    updated = True
                if updated:
                    db.session.add(current_user)
                    db.session.commit()
        except Exception:
            db.session.rollback()
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings'))
    return render_template('settings/settings.html')
@app.route('/about')
def about():
    # Render a dedicated About page
    return render_template('about.html')


@app.route('/services')
def services():
    """Services page listing telemedicine and in-facility services"""
    telemedicine_services = [
        'Video consultations',
        'Voice consultations',
        'Secure messaging with clinicians',
        'E-prescriptions and medication management',
        'Remote monitoring and follow-up',
        'Online referrals and test ordering'
    ]

    facility_services = [
        'In-person specialist consultations',
        'Laboratory tests and imaging',
        'Minor procedures and wound care',
        'Pharmacy and medication pickup',
        'Vaccinations and preventive services',
        'Emergency and urgent care'
    ]

    return render_template('services.html',
                           telemedicine_services=telemedicine_services,
                           facility_services=facility_services)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Accept either username or email in the same field (legacy name 'email').
        login_input = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        remember = True if request.form.get('remember') else False

        if not login_input or not password:
            flash('Please enter both username/email and password', 'error')
            return render_template('auth/login.html')

        user = None
        # Try a case-insensitive username match first
        try:
            user = User.query.filter(func.lower(User.username) == login_input.lower()).first()
        except Exception:
            # Fallback to exact username if DB backend doesn't support func.lower
            user = User.query.filter_by(username=login_input).first()

        # If not found by username, try email lookup via deterministic hash
        if not user:
            user = User.query.filter_by(email_hash=_hash_value(login_input.lower())).first()

        if user and user.check_password(password):
            if user.is_active:
                login_user(user, remember=remember)
                flash('Login successful!', 'success')

                # Log login action
                audit_log = AuditLog(
                    user_id=user.id,
                    action='login',
                    description=f'User {user.get_display_name()} logged in',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()

                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Account is deactivated. Please contact administrator.', 'error')
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('auth/login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Process form data
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            phone = request.form.get('phone', '').strip()
            date_of_birth = request.form.get('date_of_birth', '').strip()

            # Validate required fields
            if not all([username, email, password, first_name, last_name]):
                flash('Please fill in all required fields', 'error')
                return render_template('auth/signup.html')

            # Validate password strength
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return render_template('auth/signup.html')

            # Check if user exists
            if User.query.filter_by(email_hash=_hash_value(email)).first():
                flash('Email already registered', 'error')
                return render_template('auth/signup.html')

            if User.query.filter_by(username=username).first():
                flash('Username already taken', 'error')
                return render_template('auth/signup.html')

            # Create new user
            user = User(
                username=username,
                email=email,
                role='patient',
                is_active=True
            )
            user.set_password(password)
            user.first_name = first_name
            user.last_name = last_name
            if phone:
                user.phone = phone

            db.session.add(user)
            db.session.commit()  # Commit to get user ID

            # Create patient profile
            patient = Patient(user_id=user.id)

            # Optional patient fields (only set if provided)
            gender = request.form.get('gender', '').strip() or None
            blood_type = request.form.get('blood_type', '').strip() or None
            address = request.form.get('address', '').strip() or None
            city = request.form.get('city', '').strip() or None
            country = request.form.get('country', '').strip() or None
            postal_code = request.form.get('postal_code', '').strip() or None
            occupation = request.form.get('occupation', '').strip() or None
            nationality = request.form.get('nationality', '').strip() or None
            marital_status = request.form.get('marital_status', '').strip() or None
            preferred_language = request.form.get('preferred_language', '').strip() or None
            height_cm = request.form.get('height_cm', '').strip() or None
            weight_kg = request.form.get('weight_kg', '').strip() or None
            id_number = request.form.get('id_number', '').strip() or None
            emergency_contact = request.form.get('emergency_contact', '').strip() or None
            insurance_provider = request.form.get('insurance_provider', '').strip() or None
            insurance_number = request.form.get('insurance_number', '').strip() or None
            current_medications = request.form.get('current_medications', '').strip() or None
            medical_history = request.form.get('medical_history', '').strip() or None

            # Server-side validation helpers
            def _valid_height(h):
                try:
                    v = float(h)
                    return 30.0 <= v <= 272.0
                except Exception:
                    return False

            def _valid_weight(w):
                try:
                    v = float(w)
                    return 1.0 <= v <= 500.0
                except Exception:
                    return False

            def _valid_dob(d):
                try:
                    dob_dt = datetime.strptime(d, '%Y-%m-%d').date()
                    today = datetime.now(timezone.utc).date()
                    if dob_dt > today:
                        return False
                    age = today.year - dob_dt.year - ((today.month, today.day) < (dob_dt.month, dob_dt.day))
                    return 0 <= age <= 130
                except Exception:
                    return False

            try:
                if date_of_birth:
                    if _valid_dob(date_of_birth):
                        user.date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
                    else:
                        if app.config.get('STRICT_PROFILE_VALIDATION', False):
                            flash('Date of birth is invalid. Please correct it.', 'error')
                            return render_template('auth/signup.html')
                        else:
                            flash('Date of birth looks invalid and was not saved.', 'warning')
                            user.date_of_birth = None
            except Exception:
                user.date_of_birth = None

            # assign optional patient fields
            if gender:
                patient.gender = gender
            if blood_type:
                patient.blood_type = blood_type
            if address:
                patient.address = address
            if city:
                patient.city = city
            if country:
                patient.country = country
            if postal_code:
                patient.postal_code = postal_code
            if occupation:
                patient.occupation = occupation
            if nationality:
                patient.nationality = nationality
            if marital_status:
                patient.marital_status = marital_status
            if preferred_language:
                patient.preferred_language = preferred_language
            if id_number:
                patient.id_number = id_number
            if emergency_contact:
                patient.emergency_contact = emergency_contact
            if insurance_provider:
                patient.insurance_provider = insurance_provider
            if insurance_number:
                patient.insurance_number = insurance_number
            if current_medications:
                patient.current_medications = current_medications
            if medical_history:
                patient.medical_history = medical_history

            # numeric conversions with validation
            if height_cm:
                if _valid_height(height_cm):
                    patient.height_cm = float(height_cm)
                else:
                    if app.config.get('STRICT_PROFILE_VALIDATION', False):
                        flash('Height value is invalid. Please correct it.', 'error')
                        return render_template('auth/signup.html')
                    else:
                        flash('Height value looks out of range and was not saved.', 'warning')
            if weight_kg:
                if _valid_weight(weight_kg):
                    patient.weight_kg = float(weight_kg)
                else:
                    if app.config.get('STRICT_PROFILE_VALIDATION', False):
                        flash('Weight value is invalid. Please correct it.', 'error')
                        return render_template('auth/signup.html')
                    else:
                        flash('Weight value looks out of range and was not saved.', 'warning')
            db.session.add(patient)
            db.session.commit()

            flash('Account created successfully! Please login with your credentials.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'error')
            print(f"Signup error: {str(e)}")  # For debugging
            return render_template('auth/signup.html')

    return render_template('auth/signup.html')

@app.route('/logout')
@login_required
def logout():
    # Log logout action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='logout',
        description=f'User {current_user.username} logged out',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/patient/dashboard')
@login_required
def patient_dashboard():
    try:
        if current_user.role != 'patient':
            flash('Access denied', 'error')
            return redirect(url_for('index'))
        
        print(f"Loading dashboard for patient: {current_user.id}")  # Debug log
        
        # Find patient by user_id, not patient.id
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            print("Patient profile not found, creating one...")  # Debug log
            # Create patient profile if it doesn't exist
            patient = Patient(user_id=current_user.id)
            db.session.add(patient)
            db.session.commit()
            flash('Patient profile created successfully', 'success')
        
        print(f"Patient profile found: {patient.id}")  # Debug log
        
        # Get upcoming appointments for dashboard with proper data structure
        upcoming_appointments = []
        try:
            # Use timezone-aware datetime to fix deprecation warning
            from datetime import timezone
            now = datetime.now(timezone.utc)
            
            upcoming_appointments_data = db.session.query(
                Appointment,
                Doctor,
                User
            ).join(
                Doctor, Appointment.doctor_id == Doctor.id
            ).join(
                User, Doctor.user_id == User.id
            ).filter(
                Appointment.patient_id == patient.id,
                Appointment.status.in_(['confirmed', 'scheduled']),
                Appointment.appointment_date > now
            ).order_by(Appointment.appointment_date.asc()).limit(5).all()
            
            # Convert to template-friendly format with proper structure
            for appointment, doctor, user in upcoming_appointments_data:
                upcoming_appointments.append({
                    'id': appointment.id,
                    'appointment_date': appointment.appointment_date,
                    'consultation_type': appointment.consultation_type,
                    'symptoms': appointment.symptoms,
                    'status': appointment.status,
                    'doctor': {
                        'id': doctor.id,
                        'specialization': doctor.specialization,
                        'user': {
                            'id': user.id,
                            'first_name': user.first_name,
                            'last_name': user.last_name
                        }
                    }
                })
                
            print(f"Found {len(upcoming_appointments)} upcoming appointments")  # Debug log
            
        except Exception as e:
            print(f"Error loading appointments: {e}")  # Debug log
            import traceback
            traceback.print_exc()
            # Continue without appointments if there's an error
        
        # Get patient vitals if available
        vitals = None
        try:
            vitals = PatientVital.query.filter_by(patient_id=patient.id).order_by(PatientVital.recorded_at.desc()).first()
        except Exception as e:
            print(f"Error loading vitals: {e}")  # Debug log
            # Table might not exist yet, that's OK
        
        # Calculate BMI if height and weight are available
        bmi = None
        bmi_category = None
        try:
            if patient.height_cm and patient.weight_kg:
                height_m = patient.height_cm / 100
                bmi = round(patient.weight_kg / (height_m * height_m), 1)
                if bmi < 18.5:
                    bmi_category = 'Underweight'
                elif bmi < 25:
                    bmi_category = 'Normal'
                elif bmi < 30:
                    bmi_category = 'Overweight'
                else:
                    bmi_category = 'Obese'
        except Exception as e:
            print(f"Error calculating BMI: {e}")  # Debug log
        
        # Get medications and allergies
        medications = []
        allergies = []
        try:
            if patient.current_medications:
                medications = [med.strip() for med in patient.current_medications.split(',') if med.strip()]
            if patient.allergies:
                allergies = [allergy.strip() for allergy in patient.allergies.split(',') if allergy.strip()]
        except Exception as e:
            print(f"Error processing medications/allergies: {e}")  # Debug log
        
        # Recent activity (simplified - you can enhance this)
        recent_activity = []
        try:
            # Get recent communications
            recent_comms = db.session.query(
                Communication,
                Appointment
            ).join(
                Appointment, Communication.appointment_id == Appointment.id
            ).filter(
                Appointment.patient_id == patient.id
            ).order_by(Communication.timestamp.desc()).limit(5).all()
            
            for comm, apt in recent_comms:
                doctor_name = "Doctor"
                try:
                    if apt and apt.doctor and apt.doctor.user:
                        doctor_name = f"Dr. {apt.doctor.user.first_name}"
                except Exception:
                    pass
                    
                recent_activity.append({
                    'type': 'message',
                    'time': comm.timestamp,
                    'text': f"Message from {doctor_name}"
                })
        except Exception as e:
            print(f"Error loading recent activity: {e}")  # Debug log
        
        print("Rendering dashboard template...")  # Debug log
        
        return render_template('patient/patient_dashboard.html', 
                             user=current_user, 
                             patient=patient,
                             appointments=upcoming_appointments,  # This is now a list of dictionaries
                             vitals=vitals,
                             bmi=bmi,
                             bmi_category=bmi_category,
                             medications=medications,
                             allergies=allergies,
                             recent_activity=recent_activity)
                             
    except Exception as e:
        print(f"Critical error in patient dashboard: {e}")  # Debug log
        import traceback
        traceback.print_exc()  # Print full traceback
        flash('Error loading dashboard. Please try again.', 'error')
        return redirect(url_for('index'))

# Patient Appointments Page
@app.route('/patient/appointment')
@login_required
def patient_appointment():
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    patient = current_user.patient_profile
    if not patient:
        flash('Patient profile not found', 'error')
        return redirect(url_for('patient_dashboard'))
    
    # Get all doctors for the booking form - properly structured
    doctors_data = db.session.query(Doctor, User).join(
        User, Doctor.user_id == User.id
    ).filter(Doctor.availability == True).all()
    
    # Convert to a more template-friendly format
    doctors = []
    for doctor, user in doctors_data:
        doctors.append({
            'id': doctor.id,
            'user': {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name
            },
            'specialization': doctor.specialization,
            'consultation_fee': doctor.consultation_fee
        })
    
    # Get categorized appointments - properly flatten and categorize
    try:
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)
        
        appointments_query = db.session.query(
            Appointment,
            Doctor,
            User,
            Payment
        ).join(
            Doctor, Appointment.doctor_id == Doctor.id
        ).join(
            User, Doctor.user_id == User.id
        ).outerjoin(
            Payment, Appointment.id == Payment.appointment_id
        ).filter(
            Appointment.patient_id == patient.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Categorize appointments
        upcoming = []
        pending_confirmation = []
        completed = []
        rescheduled = []
        
        for appointment, doctor, user, payment in appointments_query:
            # Determine payment status
            payment_status = 'pending'
            if payment:
                payment_status = payment.status
            elif appointment.status == 'completed':
                payment_status = 'completed'
            
            appointment_data = {
                'id': appointment.id,
                'doctor': {
                    'id': doctor.id,
                    'user': {
                        'id': user.id,
                        'first_name': user.first_name,
                        'last_name': user.last_name
                    },
                    'specialization': doctor.specialization,
                    'consultation_fee': float(doctor.consultation_fee) if doctor.consultation_fee else 0.0
                },
                'appointment_date': appointment.appointment_date,
                'appointment_date_formatted': appointment.appointment_date.strftime('%d %b %Y') if appointment.appointment_date else None,
                'appointment_time': appointment.appointment_date.strftime('%H:%M') if appointment.appointment_date else None,
                'consultation_type': appointment.consultation_type,
                'symptoms': appointment.symptoms,
                'notes': appointment.notes,
                'status': appointment.status,
                'payment_status': payment_status,
                'rating': appointment.rating if hasattr(appointment, 'rating') else None,
                'created_at': appointment.created_at
            }
            
            # Categorize based on status and date
            if appointment.status == 'completed':
                completed.append(appointment_data)
            elif appointment.status == 'rescheduled':
                rescheduled.append(appointment_data)
            elif appointment.status == 'pending':
                pending_confirmation.append(appointment_data)
            elif appointment.status in ['confirmed', 'scheduled']:
                upcoming.append(appointment_data)
            else:
                # Default to pending confirmation for unknown statuses
                pending_confirmation.append(appointment_data)
        
        appointments_data = {
            'upcoming': upcoming,
            'pending_confirmation': pending_confirmation,
            'completed': completed,
            'rescheduled': rescheduled
        }
    except Exception as e:
        print(f"Error getting appointments: {e}")
        import traceback
        traceback.print_exc()
        appointments_data = {
            'upcoming': [],
            'pending_confirmation': [],
            'completed': [],
            'rescheduled': []
        }


    return render_template('patient/appointment.html', 
                         user=current_user, 
                         patient=patient,
                         doctors=doctors,
                         upcoming=appointments_data.get('upcoming', []),
                         pending_confirmation=appointments_data.get('pending_confirmation', []),
                         completed=appointments_data.get('completed', []),
                         rescheduled=appointments_data.get('rescheduled', []))

@app.route('/patient/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_patient_profile():
    # Only patients may edit their patient profile here
    if current_user.role != 'patient':
        flash('Only patients can edit patient profiles.', 'error')
        return redirect(url_for('index'))

    # Ensure a Patient row exists for this user
    patient = current_user.patient_profile
    if not patient:
        patient = Patient(user_id=current_user.id)
        db.session.add(patient)
        db.session.commit()

    if request.method == 'POST':
        # Basic user fields
        first_name = request.form.get('first_name', '').strip() or None
        last_name = request.form.get('last_name', '').strip() or None
        phone = request.form.get('phone', '').strip() or None
        dob = request.form.get('date_of_birth', '').strip() or None

        if first_name is not None:
            current_user.first_name = first_name
        if last_name is not None:
            current_user.last_name = last_name
        if phone is not None:
            current_user.phone = phone

        try:
            if dob:
                current_user.date_of_birth = datetime.strptime(dob, '%Y-%m-%d').date()
            else:
                current_user.date_of_birth = None
        except Exception:
            pass

        # patient optional fields
        patient.gender = request.form.get('gender', '').strip() or None
        patient.blood_type = request.form.get('blood_type', '').strip() or None
        patient.address = request.form.get('address', '').strip() or None
        patient.city = request.form.get('city', '').strip() or None
        patient.country = request.form.get('country', '').strip() or None
        patient.postal_code = request.form.get('postal_code', '').strip() or None
        patient.occupation = request.form.get('occupation', '').strip() or None
        patient.nationality = request.form.get('nationality', '').strip() or None
        patient.marital_status = request.form.get('marital_status', '').strip() or None
        patient.preferred_language = request.form.get('preferred_language', '').strip() or None
        patient.id_number = request.form.get('id_number', '').strip() or None
        patient.emergency_contact = request.form.get('emergency_contact', '').strip() or None
        patient.insurance_provider = request.form.get('insurance_provider', '').strip() or None
        patient.insurance_number = request.form.get('insurance_number', '').strip() or None
        patient.current_medications = request.form.get('current_medications', '').strip() or None
        patient.medical_history = request.form.get('medical_history', '').strip() or None

        try:
            h = request.form.get('height_cm', '').strip()
            w = request.form.get('weight_kg', '').strip()
            if h:
                patient.height_cm = float(h)
            else:
                patient.height_cm = None
            if w:
                patient.weight_kg = float(w)
            else:
                patient.weight_kg = None
        except Exception:
            pass

        # validate server-side DOB/height/weight again before commit
        def _valid_height(h):
            try:
                v = float(h)
                return 30.0 <= v <= 272.0
            except Exception:
                return False

        def _valid_weight(w):
            try:
                v = float(w)
                return 1.0 <= v <= 500.0
            except Exception:
                return False

        def _valid_dob(d):
            try:
                dob_dt = datetime.strptime(d, '%Y-%m-%d').date()
                today = datetime.now(timezone.utc).date()
                if dob_dt > today:
                    return False
                age = today.year - dob_dt.year - ((today.month, today.day) < (dob_dt.month, dob_dt.day))
                return 0 <= age <= 130
            except Exception:
                return False

        # Ensure stored numeric values are within reasonable ranges, otherwise clear and warn or block
        try:
            if current_user.date_of_birth:
                # already parsed earlier
                pass
        except Exception:
            pass

        if patient.height_cm is not None:
            try:
                if not _valid_height(patient.height_cm):
                    if app.config.get('STRICT_PROFILE_VALIDATION', False):
                        flash('Height value is invalid. Please correct it.', 'error')
                        return redirect(url_for('edit_patient_profile'))
                    else:
                        patient.height_cm = None
                        flash('Height out of range; cleared.', 'warning')
            except Exception:
                patient.height_cm = None

        if patient.weight_kg is not None:
            try:
                if not _valid_weight(patient.weight_kg):
                    if app.config.get('STRICT_PROFILE_VALIDATION', False):
                        flash('Weight value is invalid. Please correct it.', 'error')
                        return redirect(url_for('edit_patient_profile'))
                    else:
                        patient.weight_kg = None
                        flash('Weight out of range; cleared.', 'warning')
            except Exception:
                patient.weight_kg = None

        try:
            db.session.commit()
            flash('Profile updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile: ' + str(e), 'error')

        return redirect(url_for('edit_patient_profile'))

    # GET -> render form with existing values
    return render_template('patient/edit_profile.html', user=current_user, patient=patient)

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email_hash=_hash_value(email)).first()
        
        if user:
            # Generate reset token
            token = s.dumps(email, salt='password-reset-salt')
            
            # Create reset URL
            reset_url = url_for('reset_password', token=token, _external=True)
            
            try:
                # Send password reset email
                msg = Message(
                    subject='MAKOKHA MEDICAL CENTRE - Password Reset Request',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[email],
                    html=render_template('email/password_reset.html', 
                                       user=user, 
                                       reset_url=reset_url)
                )
                mail.send(msg)
                
                # Log the action
                audit_log = AuditLog(
                    user_id=user.id,
                    action='password_reset_request',
                    description=f'Password reset requested for {email}',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()
                
            except Exception as e:
                flash('Error sending email. Please try again later.', 'error')
                return render_template('auth/forgot_password.html')
            
            # Always show success message (security best practice)
            flash('If an account exists with this email, you will receive a password reset link shortly.', 'success')
        else:
            # Still show success message for security (don't reveal if email exists)
            flash('If an account exists with this email, you will receive a password reset link shortly.', 'success')
        
        return redirect(url_for('forgot_password'))
    
    return render_template('auth/forgot_password.html')

# Reset Password Route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verify token (valid for 1 hour)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid password reset link. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email_hash=_hash_value(email)).first()
    if not user:
        flash('Invalid password reset link.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        # Validate password strength
        if not validate_password_strength(new_password):
            flash('Password does not meet security requirements.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        # Log the action
        audit_log = AuditLog(
            user_id=user.id,
            action='password_reset_success',
            description='Password reset successfully',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Your password has been reset successfully. Please log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/reset_password.html', token=token)

# Password Strength Validation Function
def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False
    
    # Check for uppercase, lowercase, numbers, and special characters
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    return has_upper and has_lower and has_digit and has_special

# Generate Random Password (optional feature)
@app.route('/generate_password')
def generate_password():
    """Generate a secure random password"""
    length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return jsonify({'password': password})

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Real-time statistics from database
    stats = {
        'total_patients': Patient.query.count(),
        'total_doctors': Doctor.query.count(),
        'total_appointments': Appointment.query.count(),
        'pending_appointments': Appointment.query.filter_by(status='scheduled').count(),
        'completed_appointments': Appointment.query.filter_by(status='completed').count(),
        'cancelled_appointments': Appointment.query.filter_by(status='cancelled').count(),
        'today_appointments': Appointment.query.filter(
            db.func.date(Appointment.appointment_date) == datetime.today().date()
        ).count()
    }
    
    # Recent activity from audit logs
    recent_activities = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    # Today's appointments: join Appointment -> Patient -> PatientUser and Appointment -> Doctor -> DoctorUser
    PatientUser = aliased(User)
    DoctorUser = aliased(User)
    today_appointments = db.session.query(
        Appointment, Patient, Doctor, PatientUser, DoctorUser
    ).join(
        Patient, Appointment.patient_id == Patient.id
    ).join(
        PatientUser, Patient.user_id == PatientUser.id
    ).join(
        Doctor, Appointment.doctor_id == Doctor.id
    ).join(
        DoctorUser, Doctor.user_id == DoctorUser.id
    ).filter(
        db.func.date(Appointment.appointment_date) == datetime.today().date()
    ).order_by(Appointment.appointment_date).all()
    
    # System metrics (these can be real if you have monitoring)
    system_metrics = {
        'server_uptime': 99.8,  # This would come from your monitoring system
        'database_performance': 95,
        'storage_usage': 75,
        'network_latency': 98
    }
    
    return render_template('admin/admin_dashboard.html', 
                         stats=stats,
                         recent_activities=recent_activities,
                         today_appointments=today_appointments,
                         system_metrics=system_metrics)


@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    try:
        # Load doctor profile
        doctor = current_user.doctor_profile
        if not doctor:
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        
        if not doctor:
            flash('Doctor profile not found', 'error')
            return redirect(url_for('index'))

        # Today's appointments for this doctor (filter by date only, not time)
        try:
            from datetime import datetime, timezone, date
            today = date.today()
            # Filter appointments where the date part matches today
            appointments = []
            all_appointments = Appointment.query.filter_by(doctor_id=doctor.id).order_by(Appointment.appointment_date).all()
            for appt in all_appointments:
                appt_date = appt.appointment_date.date() if appt.appointment_date else None
                if appt_date == today:
                    appointments.append(appt)
        except Exception as e:
            print(f"Error loading appointments: {e}")
            appointments = []

        # Patients seen this week
        from datetime import datetime, timedelta, timezone
        now_utc = datetime.now(timezone.utc)
        start_week = now_utc - timedelta(days=now_utc.weekday())
        
        try:
            from sqlalchemy import func
            patients_this_week_result = db.session.query(func.count(func.distinct(Appointment.patient_id))).filter(
                Appointment.doctor_id == doctor.id,
                Appointment.appointment_date >= start_week
            ).scalar()
            patients_this_week = int(patients_this_week_result) if patients_this_week_result else 0
        except Exception as e:
            print(f"Error counting patients this week: {e}")
            patients_this_week = 0

        # Pending prescriptions (appointments with status 'scheduled' and not completed)
        try:
            pending_prescriptions = Appointment.query.filter_by(doctor_id=doctor.id, status='scheduled').count()
        except Exception as e:
            print(f"Error counting pending prescriptions: {e}")
            pending_prescriptions = 0

        # Urgent cases (appointments with status 'urgent')
        try:
            urgent_cases = Appointment.query.filter_by(doctor_id=doctor.id, status='urgent').count()
        except Exception as e:
            print(f"Error counting urgent cases: {e}")
            urgent_cases = 0

        # Helper to format last visit as 'time ago' string
        def format_timeago(dt):
            if not dt:
                return "N/A"
            now = datetime.now(timezone.utc)
            # Ensure dt is timezone-aware (convert if naive)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            diff = now - dt if now > dt else dt - now
            seconds = diff.total_seconds()
            if seconds < 60:
                return f"{int(seconds)} seconds ago"
            elif seconds < 3600:
                return f"{int(seconds // 60)} minutes ago"
            elif seconds < 86400:
                return f"{int(seconds // 3600)} hours ago"
            elif seconds < 604800:
                return f"{int(seconds // 86400)} days ago"
            else:
                return dt.strftime('%b %d, %Y')

        # Recent patients (last 6 unique patients by last appointment)
        recent_patients = []
        try:
            from sqlalchemy import desc
            appts = Appointment.query.filter_by(doctor_id=doctor.id).order_by(desc(Appointment.appointment_date)).all()
            seen = set()
            for appt in appts:
                pid = appt.patient_id
                if pid not in seen:
                    patient = db.session.get(Patient, pid)
                    if patient and patient.user:
                        recent_patients.append({
                            'user': patient.user,
                            'last_visit': format_timeago(appt.appointment_date)
                        })
                        seen.add(pid)
                if len(recent_patients) >= 6:
                    break
        except Exception as e:
            print(f"Error loading recent patients: {e}")
            recent_patients = []

        # Recent activity (communications with user info for profile pictures)
        recent_activity = []
        try:
            from sqlalchemy import desc
            recent_comms = db.session.query(Communication).filter_by().order_by(desc(Communication.timestamp)).limit(10).all()
            seen_comms = set()
            for comm in recent_comms:
                if comm.sender_id not in seen_comms:
                    sender = db.session.get(User, comm.sender_id)
                    if sender:
                        recent_activity.append({
                            'type': 'message',
                            'text': f"Message from {sender.get_display_name()}",
                            'user': sender,
                            'timestamp': comm.timestamp
                        })
                        seen_comms.add(comm.sender_id)
                if len(recent_activity) >= 10:
                    break
        except Exception as e:
            print(f"Error loading recent activity: {e}")
            recent_activity = []

        return render_template(
            'doctor/doctor_dashboard.html',
            doctor=doctor,
            appointments=appointments,
            patients_this_week=patients_this_week,
            pending_prescriptions=pending_prescriptions,
            urgent_cases=urgent_cases,
            recent_patients=recent_patients,
            recent_activity=recent_activity
        )
    
    except Exception as e:
        print(f"Critical error in doctor_dashboard: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading dashboard. Please try again.', 'error')
        return redirect(url_for('index'))
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/api/debug/memory')
@login_required
def debug_memory():
    """Debug endpoint to check memory usage"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    
    return jsonify({
        'rss_mb': memory_info.rss / 1024 / 1024,
        'vms_mb': memory_info.vms / 1024 / 1024,
        'percent': process.memory_percent(),
        'active_users': len(user_sockets),
        'active_calls': len(active_calls)
    })

@app.route('/api/debug/db-check')
def debug_db_check():
    """Debug endpoint to check database status"""
    try:
        # Check if tables exist
        tables = {
            'users': User.query.first() is not None,
            'patients': Patient.query.first() is not None,
            'doctors': Doctor.query.first() is not None,
            'appointments': Appointment.query.first() is not None,
            'payments': Payment.query.first() is not None
        }
        
        # Check appointment columns
        appointment_columns = []
        try:
            test_appt = Appointment()
            appointment_columns = [
                'urgency' if hasattr(test_appt, 'urgency') else 'MISSING: urgency',
                'rating' if hasattr(test_appt, 'rating') else 'MISSING: rating'
            ]
        except Exception as e:
            appointment_columns = [f'Error: {str(e)}']
        
        return jsonify({
            'database_connected': True,
            'tables_exist': tables,
            'appointment_columns': appointment_columns,
            'total_appointments': Appointment.query.count()
        })
    except Exception as e:
        return jsonify({'database_connected': False, 'error': str(e)})

@app.route('/admin/patients')
@login_required
def admin_patients():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    # Parse filters from query string
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()
    blood_type = request.args.get('blood_type', '').strip()
    from_date = request.args.get('from_date', '').strip()

    # Build base query for patients with eager user load
    query = Patient.query.options(joinedload(Patient.user))
    try:
        from sqlalchemy import or_
        if search:
            if '@' in search:
                # email search by deterministic hash
                email_hash = _hash_value(search)
                query = query.join(User).filter(User.email_hash == email_hash)
            else:
                query = query.join(User).filter(
                    or_(
                        User.username.ilike(f"%{search}%"),
                        User.first_name.ilike(f"%{search}%"),
                        User.last_name.ilike(f"%{search}%")
                    )
                )

        if status and status.lower() != 'all status' and status.lower() != 'all':
            if status.lower() == 'active':
                query = query.join(User).filter(User.is_active == True)
            elif status.lower() == 'inactive':
                query = query.join(User).filter(User.is_active == False)

        if blood_type and blood_type.lower() not in ('all blood types', 'all'):
            query = query.filter(Patient.blood_type == blood_type)

        if from_date:
            try:
                fd = datetime.fromisoformat(from_date).date()
                # filter users created on or after this date
                query = query.join(User).filter(func.date(User.created_at) >= fd)
            except Exception:
                pass

        patients = query.all()
    except Exception:
        # Fallback to full list on any unexpected error
        patients = Patient.query.options(joinedload(Patient.user)).all()

    # Compute dashboard statistics from real data
    total_patients = len(patients)

    # Active today: distinct patients with an appointment today
    today = date.today()
    active_today_q = db.session.query(func.count(distinct(Appointment.patient_id))).filter(
        func.date(Appointment.appointment_date) == today
    )
    try:
        active_today = int(active_today_q.scalar() or 0)
    except Exception:
        active_today = 0

    # New this month: users created this month with role patient
    first_day = today.replace(day=1)
    try:
        new_this_month = User.query.filter(
            User.role == 'patient',
            User.created_at >= datetime.combine(first_day, datetime.min.time())
        ).count()
    except Exception:
        new_this_month = 0

    # Pending records: medical records created in the last 7 days (as a reasonable definition)
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    try:
        pending_records = MedicalRecord.query.filter(MedicalRecord.created_at >= seven_days_ago).count()
    except Exception:
        pending_records = 0

    # Build per-patient metadata: visits count and last visit
    patient_items = []
    for patient in patients:
        try:
            visits = Appointment.query.filter_by(patient_id=patient.id).count()
            last_appt = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.appointment_date.desc()).first()
            last_visit = last_appt.appointment_date if last_appt else None
            status = 'Active' if getattr(patient.user, 'is_active', True) else 'Inactive'
        except Exception:
            visits = 0
            last_visit = None
            status = 'Active'

        patient_items.append({
            'patient': patient,
            'visits': visits,
            'last_visit': last_visit,
            'status': status
        })

    return render_template('admin/patients.html',
                         patients=patients,
                         patient_items=patient_items,
                         stats={
                             'total_patients': total_patients,
                             'active_today': active_today,
                             'new_this_month': new_this_month,
                             'pending_records': pending_records
                         },
                         filters={
                             'search': search,
                             'status': status,
                             'blood_type': blood_type,
                             'from_date': from_date
                         },
                         now=datetime.now(timezone.utc))


@app.route('/admin/patients_data', methods=['GET'])
@login_required
def admin_patients_data():
    """Return patients as JSON for AJAX filtering with paging."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    # params
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()
    blood_type = request.args.get('blood_type', '').strip()
    from_date = request.args.get('from_date', '').strip()
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except Exception:
        page = 1
    try:
        per_page = int(request.args.get('per_page', 12))
        if per_page < 1:
            per_page = 12
    except Exception:
        per_page = 12

    query = Patient.query.options(joinedload(Patient.user))
    try:
        from sqlalchemy import or_
        if search:
            # match username, first name, last name, email (partial) or phone
            query = query.join(User).filter(
                or_(
                    User.username.ilike(f"%{search}%"),
                    User.first_name.ilike(f"%{search}%"),
                    User.last_name.ilike(f"%{search}%"),
                    User.email.ilike(f"%{search}%"),
                    User.phone.ilike(f"%{search}%")
                )
            )

        if status and status.lower() not in ('', 'all', 'all status'):
            if status.lower() == 'active':
                query = query.join(User).filter(User.is_active == True)
            elif status.lower() == 'inactive':
                query = query.join(User).filter(User.is_active == False)

        if blood_type and blood_type.lower() not in ('', 'all', 'all blood types'):
            query = query.filter(Patient.blood_type == blood_type)

        if from_date:
            try:
                fd = datetime.fromisoformat(from_date).date()
                query = query.join(User).filter(func.date(User.created_at) >= fd)
            except Exception:
                pass

        total = query.count()
        pages = (total + per_page - 1) // per_page
        patients = query.order_by(Patient.id.desc()).offset((page - 1) * per_page).limit(per_page).all()

        items = []
        for patient in patients:
            try:
                visits = Appointment.query.filter_by(patient_id=patient.id).count()
                last_appt = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.appointment_date.desc()).first()
                last_visit = last_appt.appointment_date.isoformat() if last_appt else None
                status_text = 'Active' if getattr(patient.user, 'is_active', True) else 'Inactive'
            except Exception:
                visits = 0
                last_visit = None
                status_text = 'Active'

            user = getattr(patient, 'user', None)
            items.append({
                'id': patient.id,
                'visits': visits,
                'last_visit': last_visit,
                'status': status_text,
                'blood_type': patient.blood_type,
                'emergency_contact': patient.emergency_contact,
                'allergies': patient.allergies,
                'insurance_provider': patient.insurance_provider,
                'user': {
                    'id': user.id if user else None,
                    'username': user.username if user else None,
                    'first_name': user.first_name if user else None,
                    'last_name': user.last_name if user else None,
                    'email': user.email if user else None,
                    'phone': user.phone if user else None,
                    'profile_picture': getattr(user, 'profile_picture', None) if user else None,
                    'date_of_birth': user.date_of_birth.isoformat() if user and getattr(user, 'date_of_birth', None) else None,
                }
            })

        return jsonify({'items': items, 'total': total, 'page': page, 'per_page': per_page, 'pages': pages})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))

    data = request.form
    # support FormData from fetch/XHR as well as standard form posts
    if not data:
        data = request.get_json() or {}
    role = data.get('role')
    username = data.get('username') or data.get('usernames')
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone = data.get('phone')

    # validate required fields
    if not all([role, email, password, first_name, last_name, username]):
        msg = 'All fields are required.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    # check username uniqueness
    if User.query.filter_by(username=username).first():
        msg = 'Username already taken.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    # check email uniqueness
    if User.query.filter_by(email_hash=_hash_value(email)).first():
        msg = 'Email already registered.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    try:
        # create user and set encrypted fields via properties
        user = User(
            username=username,
            role=role,
            is_active=True
        )
        user.email = email
        user.first_name = first_name
        user.last_name = last_name
        if phone:
            user.phone = phone
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        # create role-specific profile
        if role == 'doctor':
            doctor = Doctor(user_id=user.id)
            db.session.add(doctor)
        elif role == 'patient':
            patient = Patient(user_id=user.id)
            db.session.add(patient)

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        msg = f'Error creating user: {str(e)}'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 500
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    # Success — return JSON for AJAX or redirect for normal form post
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'user_id': user.id})

    flash('User added successfully.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>', methods=['GET'])
@login_required
def admin_get_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    u = User.query.get_or_404(user_id)
    try:
        return jsonify({
            'id': u.id,
            'username': u.username,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'email': u.email,
            'phone': u.phone,
            'role': u.role,
            'is_active': bool(u.is_active)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/users_data', methods=['GET'])
@login_required
def admin_users_data():
    """Return users as JSON for admin user management filters."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    role = request.args.get('role')
    status = request.args.get('status')

    query = User.query
    if role:
        query = query.filter(User.role == role)
    if status:
        if status == 'active':
            query = query.filter(User.is_active == True)
        elif status == 'inactive':
            query = query.filter(User.is_active == False)

    users = query.order_by(User.created_at.desc()).all()
    out = []
    for u in users:
        try:
            out.append({
                'id': u.id,
                'username': u.username,
                'first_name': u.first_name,
                'last_name': u.last_name,
                'email': u.email,
                'phone': u.phone,
                'role': u.role,
                'is_active': bool(u.is_active),
                'created_at': u.created_at.isoformat() if u.created_at else None
            })
        except Exception:
            # If decryption fails for a field, continue with raw values where possible
            out.append({
                'id': u.id,
                'username': getattr(u, 'username', ''),
                'first_name': getattr(u, 'encrypted_first_name', '') if getattr(u, 'encrypted_first_name', None) else '',
                'last_name': getattr(u, 'encrypted_last_name', '') if getattr(u, 'encrypted_last_name', None) else '',
                'email': None,
                'phone': None,
                'role': getattr(u, 'role', ''),
                'is_active': bool(getattr(u, 'is_active', False)),
                'created_at': u.created_at.isoformat() if getattr(u, 'created_at', None) else None
            })

    return jsonify({'users': out})


@app.route('/admin/update_user', methods=['POST'])
@login_required
def admin_update_user():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    data = request.form or request.get_json() or {}
    try:
        uid = int(data.get('user_id'))
    except Exception:
        return jsonify({'success': False, 'error': 'Missing user_id'}), 400

    u = User.query.get_or_404(uid)

    username = data.get('username')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone = data.get('phone')
    role = data.get('role')
    password = data.get('password')

    # Basic validation
    if not all([username, email, first_name, last_name]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    # Check username/email uniqueness excluding current user
    exists = User.query.filter(User.username == username, User.id != u.id).first()
    if exists:
        return jsonify({'success': False, 'error': 'Username already taken'}), 400
    if User.query.filter(User.email_hash == _hash_value(email), User.id != u.id).first():
        return jsonify({'success': False, 'error': 'Email already registered'}), 400

    try:
        u.username = username
        u.email = email
        u.first_name = first_name
        u.last_name = last_name
        u.phone = phone
        # role change handling
        old_role = u.role
        u.role = role
        if password:
            u.set_password(password)

        db.session.add(u)
        db.session.commit()

        # ensure role-specific profile exists
        if role == 'doctor' and not Doctor.query.filter_by(user_id=u.id).first():
            db.session.add(Doctor(user_id=u.id))
        if role == 'patient' and not Patient.query.filter_by(user_id=u.id).first():
            db.session.add(Patient(user_id=u.id))
        # if role changed away from doctor/patient, we leave legacy records (optional: remove)
        db.session.commit()

        return jsonify({'success': True, 'user_id': u.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/toggle_user_status', methods=['POST'])
@login_required
def admin_toggle_user_status():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    data = request.form or request.get_json() or {}
    try:
        uid = int(data.get('user_id'))
    except Exception:
        return jsonify({'success': False, 'error': 'Missing user_id'}), 400
    u = User.query.get_or_404(uid)
    try:
        u.is_active = not bool(u.is_active)
        db.session.add(u)
        db.session.commit()
        return jsonify({'success': True, 'user_id': u.id, 'is_active': u.is_active})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/delete_user', methods=['POST'])
@login_required
def admin_delete_user():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    data = request.form or request.get_json() or {}
    try:
        uid = int(data.get('user_id'))
    except Exception:
        return jsonify({'success': False, 'error': 'Missing user_id'}), 400

    if uid == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400

    u = User.query.get_or_404(uid)
    try:
        role = request.args.get('role')
        status = request.args.get('status')
        search = request.args.get('search', '').strip()

        # paging
        try:
            page = int(request.args.get('page', 1))
            if page < 1:
                page = 1
        except Exception:
            page = 1
        try:
            per_page = int(request.args.get('per_page', 25))
            if per_page < 1:
                per_page = 25
        except Exception:
            per_page = 25

        query = User.query
        if role:
            query = query.filter(User.role == role)
        if status:
            if status == 'active':
                query = query.filter(User.is_active == True)
            elif status == 'inactive':
                query = query.filter(User.is_active == False)

        # Search: support username partial matches and exact email (by hashing)
        from sqlalchemy import or_
        if search:
            if '@' in search:
                # treat as email search (exact match via deterministic hash)
                email_hash = _hash_value(search)
                query = query.filter(User.email_hash == email_hash)
            else:
                query = query.filter(or_(User.username.ilike(f"%{search}%")))

        total = query.count()
        users = query.order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

        out = []
        for u in users:
            try:
                out.append({
                    'id': u.id,
                    'username': u.username,
                    'first_name': u.first_name,
                    'last_name': u.last_name,
                    'email': u.email,
                    'phone': u.phone,
                    'role': u.role,
                    'is_active': bool(u.is_active),
                    'created_at': u.created_at.isoformat() if u.created_at else None
                })
            except Exception:
                out.append({
                    'id': u.id,
                    'username': getattr(u, 'username', ''),
                    'first_name': None,
                    'last_name': None,
                    'email': None,
                    'phone': None,
                    'role': getattr(u, 'role', ''),
                    'is_active': bool(getattr(u, 'is_active', False)),
                    'created_at': u.created_at.isoformat() if getattr(u, 'created_at', None) else None
                })

        pages = (total + per_page - 1) // per_page
        return jsonify({'users': out, 'total': total, 'page': page, 'per_page': per_page, 'pages': pages})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# Download communication file (decrypt and stream)
@app.route('/admin/communication/download/<int:comm_id>')
@login_required
def admin_download_communication_file(comm_id):
    comm = Communication.query.get_or_404(comm_id)
    # Only admins or participants should access; here we allow admins
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    # Prefer blob if available
    blob = comm.encrypted_file_blob
    if blob:
        data = decrypt_file_bytes(blob)
        if data is None:
            flash('Unable to decrypt file', 'error')
            apt = db.session.get(Appointment, comm.appointment_id)
            pid = apt.patient_id if apt else None
            return redirect(request.referrer or url_for('admin_view_patient', patient_id=pid))
        # Determine a filename from comm id and type
        filename = f"comm_{comm.id}_{comm.message_type}"
        return send_file(BytesIO(data), download_name=filename, as_attachment=True)

    # Fallback: if encrypted_file_path present, decrypt and serve
    path = comm.file_path if hasattr(comm, 'file_path') else None
    if path:
        # If path is stored as encrypted path, decrypt
        realpath = comm.file_path
        try:
            # Serve file from static if path is relative
            if realpath and (realpath.startswith('profile_pics') or realpath.startswith('uploads') or realpath.startswith('wallpapers')):
                return send_file(os.path.join(app.static_folder, realpath))
        except Exception:
            pass

    flash('No file available', 'error')
    apt = db.session.get(Appointment, comm.appointment_id)
    pid = apt.patient_id if apt else None
    return redirect(request.referrer or url_for('admin_view_patient', patient_id=pid))


# Endpoint to accept uploaded recording via POST (form-data file)
@app.route('/communication/upload_recording', methods=['POST'])
@login_required
def upload_recording():
    # Expects fields: appointment_id, message_type (voice_note | video_recording), file (binary)
    appointment_id = request.form.get('appointment_id')
    message_type = request.form.get('message_type')
    file = request.files.get('file')

    if not appointment_id or not message_type or not file:
        return jsonify({'error': 'Missing parameters'}), 400

    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        return jsonify({'error': 'Invalid appointment'}), 404

    # Determine sender as current_user
    try:
        data = file.read()

        # Offload encryption and DB save to background to avoid blocking the request thread
        def _bg_http_save(app_obj, appointment_id, sender_id, message_type, raw_bytes):
            with app_obj.app_context():
                try:
                    encrypted = encrypt_file_bytes(raw_bytes)
                    comm = Communication(
                        appointment_id=appointment_id,
                        sender_id=sender_id,
                        message_type=message_type,
                        encrypted_file_blob=encrypted
                    )
                    db.session.add(comm)
                    db.session.commit()
                    # Notify appointment room about new message
                    try:
                        socketio.emit('new_communication', {
                            'comm_id': comm.id,
                            'appointment_id': appointment_id
                        }, room=f'appointment_{appointment_id}')
                    except Exception:
                        pass
                except Exception:
                    db.session.rollback()

        socketio.start_background_task(_bg_http_save, app, appointment.id, current_user.id, message_type, data)
        # Return accepted so client can continue; final status will be emitted via Socket.IO
        return jsonify({'status': 'processing'}), 202
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Socket.IO handler to accept recording blobs as base64 (if client emits)
if SOCKETIO_AVAILABLE:
    @socketio.on('save_recording')
    def handle_save_recording(data):
        # data expected: { appointment_id, message_type, sender_id, blob_b64 }
        import base64
        appointment_id = data.get('appointment_id')
        message_type = data.get('message_type')
        sender_id = data.get('sender_id')
        blob_b64 = data.get('blob_b64')

        # Try to get the client's socket id so we can emit the result only to them
        sid = None
        try:
            # flask-socketio exposes a request object with sid in this context
            from flask import request as _flask_request
            sid = getattr(_flask_request, 'sid', None)
        except Exception:
            sid = None

        if not appointment_id or not message_type or not blob_b64:
            emit('save_recording_response', {'error': 'missing parameters'})
            return

        try:
            raw = base64.b64decode(blob_b64)
        except Exception as e:
            emit('save_recording_response', {'error': 'invalid base64'})
            return

        # Offload encryption and DB work to a background task so the socket handler returns quickly
        def _bg_save(app_obj, appointment_id, message_type, sender_id, raw_bytes, client_sid):
            with app_obj.app_context():
                try:
                    encrypted = encrypt_file_bytes(raw_bytes)
                    comm = Communication(
                        appointment_id=appointment_id,
                        sender_id=sender_id or getattr(current_user, 'id', None),
                        message_type=message_type,
                        encrypted_file_blob=encrypted
                    )
                    db.session.add(comm)
                    db.session.commit()
                    payload = {'status': 'ok', 'comm_id': comm.id}
                except Exception as e:
                    db.session.rollback()
                    payload = {'error': str(e)}

                try:
                    if client_sid:
                        socketio.emit('save_recording_response', payload, to=client_sid)
                    else:
                        # Fallback: broadcast to caller (may reach multiple clients)
                        socketio.emit('save_recording_response', payload)
                except Exception:
                    pass

        socketio.start_background_task(_bg_save, app, appointment_id, message_type, sender_id, raw, sid)

        # Immediately acknowledge receipt so the client doesn't wait
        emit('save_recording_response', {'status': 'processing'})

# Communication Routes
@app.route('/communication/<int:appointment_id>')
@login_required
def communication_dashboard(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)

    # Check if user has access to this appointment
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            flash('Access denied', 'error')
            return redirect(url_for('patient_dashboard'))
        # Load all appointments for this patient
        appointments = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.appointment_date.desc()).all()
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if appointment.doctor_id != doctor.id:
            flash('Access denied', 'error')
            return redirect(url_for('doctor_dashboard'))
        # Load all appointments for this doctor
        appointments = Appointment.query.filter_by(doctor_id=doctor.id).order_by(Appointment.appointment_date.desc()).all()
    else:
        appointments = []

    # Check payment status for this appointment
    from models import Payment
    payment = Payment.query.filter_by(appointment_id=appointment_id).order_by(Payment.created_at.desc()).first()
    payment_required = False
    payment_url = None
    if payment is None or payment.status != 'paid':
        # For patients, require payment before enabling communication features
        if current_user.role == 'patient':
            payment_required = True
            if payment:
                payment_url = url_for('payment_page', payment_id=payment.id)
            else:
                # create a placeholder payment pointing to appointment
                try:
                    p = Payment(appointment_id=appointment.id, patient_id=patient.id)
                    db.session.add(p)
                    db.session.commit()
                    payment_url = url_for('payment_page', payment_id=p.id)
                except Exception:
                    payment_url = url_for('patient_appointment')

    # Load recent messages for this appointment (limit to last 200 to avoid large queries)
    try:
        messages = Communication.query.filter_by(
            appointment_id=appointment_id
        ).order_by(Communication.timestamp.desc()).limit(200).all()
        # reverse so template receives chronological order (oldest first)
        messages = list(reversed(messages))
    except Exception:
        # fallback to safe query if something goes wrong
        messages = Communication.query.filter_by(appointment_id=appointment_id).order_by(Communication.timestamp).all()

    return render_template('communication/communication_dashboard.html',
                         appointment=appointment,
                         appointments=appointments,
                         messages=messages,
                         payment_required=payment_required,
                         payment_url=payment_url)


# Payment pages and APIs
@app.route('/payment/<int:payment_id>')
@login_required
def payment_page(payment_id):
    from models import Payment
    payment = Payment.query.get_or_404(payment_id)
    # Only patient who owns payment or admin may view
    patient = db.session.get(Patient, payment.patient_id)
    if current_user.role == 'patient' and patient.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    return render_template('payment/payment_page.html', payment=payment)


@app.route('/payment/status/<int:payment_id>')
@login_required
def payment_status(payment_id):
    from models import Payment
    payment = Payment.query.get_or_404(payment_id)
    return jsonify({'id': payment.id, 'status': payment.status, 'provider': payment.provider, 'amount': payment.amount})

@app.route('/api/user/<int:user_id>/profile')
@login_required
def get_user_profile(user_id):
    """Get user profile information including profile picture"""
    user = User.query.get_or_404(user_id)
    
    # Check if current user has permission to view this profile
    if current_user.role != 'admin' and current_user.id != user_id:
        # For doctor-patient relationships, check if they have appointments together
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            patient = Patient.query.filter_by(user_id=user_id).first()
            if not patient or not has_shared_appointment(doctor.id, patient.id):
                return jsonify({'error': 'Access denied'}), 403
        elif current_user.role == 'patient':
            patient = Patient.query.filter_by(user_id=current_user.id).first()
            doctor = Doctor.query.filter_by(user_id=user_id).first()
            if not doctor or not has_shared_appointment(doctor.id, patient.id):
                return jsonify({'error': 'Access denied'}), 403
    
    profile_data = {
        'id': user.id,
        'username': user.username,
        'name': user.get_display_name(),
        'role': user.role,
        'profile_picture_url': get_user_profile_picture_url(user)
    }
    
    return jsonify(profile_data)

def has_shared_appointment(doctor_id, patient_id):
    """Check if doctor and patient have any appointments together"""
    appointment = Appointment.query.filter_by(
        doctor_id=doctor_id,
        patient_id=patient_id
    ).first()
    return appointment is not None

@app.route('/api/appointment/<int:appointment_id>/details')
@login_required
def get_appointment_details_enhanced(appointment_id):
    """Get enhanced appointment details with profile pictures"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if not verify_appointment_access(appointment, current_user):
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = db.session.get(Doctor, appointment.doctor_id)
    doctor_user = db.session.get(User, doctor.user_id) if doctor else None
    patient = db.session.get(Patient, appointment.patient_id)
    patient_user = db.session.get(User, patient.user_id) if patient else None
    
    # Get profile picture URLs
    doctor_profile_picture = None
    if doctor_user and doctor_user.profile_picture:
        if doctor_user.profile_picture.startswith('http'):
            doctor_profile_picture = doctor_user.profile_picture
        else:
            doctor_profile_picture = url_for('profile_picture', user_id=doctor_user.id, _external=True)
    
    patient_profile_picture = None
    if patient_user and patient_user.profile_picture:
        if patient_user.profile_picture.startswith('http'):
            patient_profile_picture = patient_user.profile_picture
        else:
            patient_profile_picture = url_for('profile_picture', user_id=patient_user.id, _external=True)
    
    # Check if doctor is online
    doctor_online = doctor_user.id in user_sockets if doctor_user else False
    
    return jsonify({
        'id': appointment.id,
        'doctor_id': doctor.id if doctor else None,
        'doctor_first_name': doctor_user.first_name if doctor_user else '',
        'doctor_last_name': doctor_user.last_name if doctor_user else '',
        'doctor_specialization': doctor.specialization if doctor else '',
        'doctor_profile_picture': doctor_profile_picture,
        'doctor_online': doctor_online,
        'patient_id': patient.id if patient else None,
        'patient_first_name': patient_user.first_name if patient_user else '',
        'patient_last_name': patient_user.last_name if patient_user else '',
        'patient_profile_picture': patient_profile_picture,
        'appointment_date': appointment.appointment_date.isoformat(),
        'consultation_type': appointment.consultation_type,
        'symptoms': appointment.symptoms,
        'status': appointment.status,
        'payment_status': get_appointment_payment_status_internal(appointment_id)
    })

def get_appointment_payment_status_internal(appointment_id):
    """Internal function to get payment status"""
    payment = Payment.query.filter_by(appointment_id=appointment_id).order_by(Payment.created_at.desc()).first()
    if payment:
        return payment.status
    return 'pending'

# Add this route for appointment confirmation
@app.route('/api/appointment/<int:appointment_id>/confirm', methods=['POST'])
@login_required
@csrf.exempt
def confirm_appointment(appointment_id):
    """Confirm an appointment"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        appointment.status = 'confirmed'
        db.session.commit()
        
        # Emit socket event for real-time updates
        if SOCKETIO_AVAILABLE:
            socketio.emit('appointment_status_updated', {
                'appointment_id': appointment.id,
                'status': 'confirmed',
                'patient_id': appointment.patient_id
            })
        
        return jsonify({'success': True, 'message': 'Appointment confirmed successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this route for appointment cancellation
@app.route('/api/appointment/<int:appointment_id>/cancel', methods=['POST'])
@login_required
@csrf.exempt
def cancel_appointment(appointment_id):
    """Cancel an appointment"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        appointment.status = 'cancelled'
        db.session.commit()
        
        # Emit socket event for real-time updates
        if SOCKETIO_AVAILABLE:
            socketio.emit('appointment_status_updated', {
                'appointment_id': appointment.id,
                'status': 'cancelled',
                'patient_id': appointment.patient_id
            })
        
        return jsonify({'success': True, 'message': 'Appointment cancelled successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this route for appointment rating
@app.route('/api/appointment/<int:appointment_id>/rate', methods=['POST'])
@login_required
@csrf.exempt
def rate_appointment(appointment_id):
    """Rate a completed appointment"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access and that appointment is completed
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if appointment.status != 'completed':
        return jsonify({'success': False, 'error': 'Can only rate completed appointments'}), 400
    
    data = request.get_json()
    rating = data.get('rating')
    comment = data.get('comment', '')
    
    if not rating or not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify({'success': False, 'error': 'Invalid rating'}), 400
    
    try:
        # Update appointment with rating
        appointment.rating = rating
        if comment:
            appointment.feedback = comment
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Rating submitted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Update the payment confirmation route to fix CSRF issues
@app.route('/payment/confirm/<int:payment_id>', methods=['POST'])
@login_required
@csrf.exempt  # Remove CSRF for payment confirmations since they come from external sources
def payment_confirm(payment_id):
    """Confirm payment and redirect to patient dashboard"""
    from models import Payment
    payment = Payment.query.get_or_404(payment_id)
    
    # Verify the current user owns this payment
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if payment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        payment.status = 'paid'
        db.session.commit()
        
        # Update appointment status if needed
        appointment = db.session.get(Appointment, payment.appointment_id)
        if appointment and appointment.status == 'pending':
            appointment.status = 'confirmed'
            db.session.commit()
        
        # Emit payment status update via Socket.IO
        if SOCKETIO_AVAILABLE:
            socketio.emit('payment_status_updated', {
                'appointment_id': payment.appointment_id,
                'status': 'paid',
                'user_id': current_user.id
            })
        
        return jsonify({'success': True, 'message': 'Payment completed successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this route for payment page by appointment
@app.route('/payment/appointment/<int:appointment_id>')
@login_required
def payment_by_appointment(appointment_id):
    """Payment page for a specific appointment"""
    from models import Payment
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            flash('Access denied', 'error')
            return redirect(url_for('patient_dashboard'))
    
    # Find or create payment for this appointment
    payment = Payment.query.filter_by(appointment_id=appointment_id).first()
    if not payment:
        # Create a new payment
        doctor = db.session.get(Doctor, appointment.doctor_id)
        amount = doctor.consultation_fee if doctor and doctor.consultation_fee else 1500.00
        
        payment = Payment(
            appointment_id=appointment_id,
            patient_id=appointment.patient_id,
            amount=amount,
            currency='KES',
            status='pending'
        )
        db.session.add(payment)
        db.session.commit()
    
    return render_template('payment/payment_page.html', payment=payment)

# Update the book appointment API to include appointment confirmation
@app.route('/api/book_appointment', methods=['POST'])
@login_required
@csrf.exempt
def book_appointment():
    """Book a new appointment with initial pending status"""
    try:
        if current_user.role != 'patient':
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        print(f"Received booking data: {data}")  # Debug log
        
        # Validate required fields
        required_fields = ['doctor_id', 'date', 'consultation_type', 'symptoms']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({'success': False, 'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            return jsonify({'success': False, 'error': 'Patient profile not found'}), 404
        
        # Parse date with better error handling
        try:
            appointment_date_str = data.get('date')
            print(f"Parsing date: {appointment_date_str}")  # Debug log
            appointment_date = datetime.strptime(appointment_date_str, '%Y-%m-%dT%H:%M')
        except ValueError as e:
            print(f"Date parsing error: {e}")  # Debug log
            return jsonify({'success': False, 'error': f'Invalid date format. Use YYYY-MM-DDTHH:MM. Error: {str(e)}'}), 400
        
        # Check if doctor exists
        doctor = db.session.get(Doctor, data.get('doctor_id'))
        if not doctor:
            return jsonify({'success': False, 'error': 'Doctor not found'}), 404
        
        print(f"Creating appointment for patient {patient.id}, doctor {doctor.id}")  # Debug log
        
        # Create appointment with pending status
        appointment = Appointment(
            patient_id=patient.id,
            doctor_id=data.get('doctor_id'),
            appointment_date=appointment_date,
            consultation_type=data.get('consultation_type'),
            symptoms=data.get('symptoms'),
            status='pending',  # Set to pending until confirmed by patient
            urgency=data.get('urgency', 'routine')
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        print(f"Appointment created with ID: {appointment.id}")  # Debug log

        # Create payment intent
        try:
            amount = float(doctor.consultation_fee) if doctor and doctor.consultation_fee is not None else 1500.00

            payment = Payment(
                appointment_id=appointment.id,
                patient_id=patient.id,
                amount=amount,
                currency='KES',
                status='pending'
            )
            db.session.add(payment)
            db.session.commit()

            payment_url = url_for('payment_by_appointment', appointment_id=appointment.id, _external=False)

            return jsonify({
                'success': True, 
                'appointment_id': appointment.id, 
                'payment_url': payment_url, 
                'payment_id': payment.id,
                'message': 'Appointment booked successfully. Please complete payment and confirmation.'
            }), 201
            
        except Exception as e:
            print(f"Payment creation error: {e}")  # Debug log
            # If payment creation fails, still return appointment id
            return jsonify({
                'success': True, 
                'appointment_id': appointment.id, 
                'warning': 'Payment creation failed', 
                'error': str(e)
            }), 201
            
    except Exception as e:
        db.session.rollback()
        print(f"Booking error: {e}")  # Debug log
        import traceback
        traceback.print_exc()  # This will print the full traceback to the console
        return jsonify({'success': False, 'error': f'Internal server error: {str(e)}'}), 500

@app.route('/payment/simulate/<int:payment_id>')
@login_required
def simulate_provider(payment_id):
    """Simulated payment provider page (for testing)"""
    from models import Payment
    payment = Payment.query.get_or_404(payment_id)
    
    # Render a simulated payment page that works within modal
    csrf_token = generate_csrf_token()
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Simulated Payment - MAKOKHA MEDICAL CENTRE</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            body {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .payment-sim-card {{
                background: white;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="payment-sim-card p-4">
                        <div class="text-center mb-4">
                            <i class="fas fa-shield-alt fa-3x text-primary mb-3"></i>
                            <h3>Simulated Payment Gateway</h3>
                            <p class="text-muted">Development Environment</p>
                        </div>
                        
                        <div class="card border-0 bg-light mb-4">
                            <div class="card-body">
                                <h5 class="card-title">Payment Details</h5>
                                <div class="d-flex justify-content-between mb-2">
                                    <span>Amount:</span>
                                    <strong>{payment.amount} {payment.currency}</strong>
                                </div>
                                <div class="d-flex justify-content-between mb-2">
                                    <span>Appointment ID:</span>
                                    <strong>#{payment.appointment_id}</strong>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <span>Status:</span>
                                    <span class="badge bg-warning">Pending</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            This is a simulated payment environment for testing purposes.
                        </div>
                        
                        <form method='POST' action='{url_for('payment_confirm', payment_id=payment.id)}'>
                            <input type='hidden' name='csrf_token' value='{csrf_token}'>
                            <div class="d-grid gap-2">
                                <button type='submit' class='btn btn-success btn-lg'>
                                    <i class="fas fa-check me-2"></i>
                                    Simulate Successful Payment
                                </button>
                                <button type='button' class='btn btn-outline-secondary' onclick='window.close()'>
                                    <i class="fas fa-times me-2"></i>
                                    Cancel Payment
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Auto-close after successful payment
            function closeWindow() {{
                setTimeout(() => {{
                    window.close();
                }}, 2000);
            }}
            
            // Handle form submission
            document.querySelector('form').addEventListener('submit', function(e) {{
                e.preventDefault();
                const form = this;
                const submitBtn = form.querySelector('button[type="submit"]');
                const originalText = submitBtn.innerHTML;
                
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
                submitBtn.disabled = true;
                
                fetch(form.action, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/x-www-form-urlencoded',
                    }},
                    body: new URLSearchParams(new FormData(form))
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        submitBtn.innerHTML = '<i class="fas fa-check me-2"></i>Payment Successful!';
                        submitBtn.className = 'btn btn-success btn-lg';
                        setTimeout(() => {{
                            window.close();
                        }}, 1500);
                    }} else {{
                        throw new Error(data.error);
                    }}
                }})
                .catch(error => {{
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                    alert('Payment failed: ' + error.message);
                }});
            }});
        </script>
    </body>
    </html>
    """


# Webhook endpoint for external payment providers (exempt from CSRF)
@app.route('/payment/webhook/<provider>', methods=['POST'])
@csrf.exempt
def payment_webhook(provider):
    """Receive webhook callbacks from external payment providers.

    Example HMAC-SHA256 verification:
    - Provider signs raw request body using a shared secret and sends signature in header `X-Signature`.
    - The application looks up the secret for the provider in `app.config['PAYMENT_PROVIDER_SECRETS']`.
    """
    try:
        secret_map = app.config.get('PAYMENT_PROVIDER_SECRETS', {}) or {}
        secret = secret_map.get(provider)

        raw = request.get_data() or b''

        # Example header name for signature (common patterns vary by provider)
        signature_header = request.headers.get('X-Signature') or request.headers.get('X-Signature-SHA256')

        if secret and signature_header:
            computed = hmac.new(secret.encode('utf-8'), raw, hashlib.sha256).hexdigest()
            # Timing-safe compare
            if not hmac.compare_digest(computed, signature_header):
                return jsonify({'error': 'invalid signature'}), 400

        # Parse JSON payload
        payload = {}
        try:
            payload = request.get_json(force=True)
        except Exception:
            payload = {}

        # Providers may send different payload shapes. Example expected fields:
        # { 'payment_id': 123, 'status': 'paid', 'provider_reference': 'abc123' }
        payment_id = payload.get('payment_id') or payload.get('id') or request.args.get('payment_id')
        status = payload.get('status')
        provider_ref = payload.get('provider_reference') or payload.get('transaction_id')

        if not payment_id:
            return jsonify({'error': 'missing payment_id'}), 400

        from models import Payment
        try:
            try:
                payment = db.session.get(Payment, int(payment_id))
            except Exception:
                payment = None
        except Exception:
            payment = None

        if not payment:
            return jsonify({'error': 'payment not found'}), 404

        # Map provider statuses to our internal states
        if status in ('paid', 'success', 'completed'):
            payment.status = 'paid'
        elif status in ('failed', 'cancelled', 'declined'):
            payment.status = 'failed'
        else:
            # unknown -> store as 'pending' or set provider-specific state
            payment.status = status or payment.status or 'pending'

        if provider_ref:
            payment.provider_reference = provider_ref

        try:
            db.session.add(payment)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({'error': 'failed to update payment'}), 500

        # Return 200 to acknowledge webhook
        return jsonify({'ok': True}), 200
    except Exception as e:
        return jsonify({'error': 'exception', 'message': str(e)}), 500


# Stripe-specific webhook handler demonstrating recommended verification
@app.route('/payment/webhook/stripe', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    """Stripe webhook endpoint. Uses official Stripe library if installed.

    Configure `STRIPE_WEBHOOK_SECRET` in `config.py` / env. If the `stripe`
    package is available, we use `stripe.Webhook.construct_event` to verify
    the signature. Otherwise, the endpoint will return 501 indicating the
    stripe library is not available and you should install `stripe`.
    """
    endpoint_secret = app.config.get('STRIPE_WEBHOOK_SECRET')
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')

    if not endpoint_secret:
        return jsonify({'error': 'STRIPE_WEBHOOK_SECRET not configured'}), 500

    try:
        import stripe
    except Exception:
        # Stripe library not installed: advise installation or use generic webhook
        return jsonify({'error': 'stripe library not installed'}), 501

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig_header, secret=endpoint_secret)
    except ValueError:
        return jsonify({'error': 'invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'invalid signature'}), 400

    # Handle relevant event types
    try:
        event_type = event.get('type')
        data_obj = event.get('data', {}).get('object', {})

        if event_type == 'payment_intent.succeeded' or event_type == 'checkout.session.completed':
            # Try to find a payment_id in metadata (recommended to store mapping)
            payment_id = None
            if isinstance(data_obj, dict):
                payment_id = data_obj.get('metadata', {}).get('payment_id') or data_obj.get('id')

            if payment_id:
                from models import Payment
                try:
                    try:
                        payment = db.session.get(Payment, int(payment_id))
                    except Exception:
                        payment = None
                except Exception:
                    payment = None

                if payment:
                    payment.status = 'paid'
                    payment.provider_reference = data_obj.get('id')
                    try:
                        db.session.add(payment)
                        db.session.commit()
                    except Exception:
                        db.session.rollback()

        # Acknowledge receipt
        return jsonify({'received': True}), 200
    except Exception as e:
        return jsonify({'error': 'processing error', 'message': str(e)}), 500


# Admin view for a single patient's full details
@app.route('/admin/patient/<int:patient_id>')
@login_required
def admin_view_patient(patient_id):
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    patient = Patient.query.options(joinedload(Patient.user)).get_or_404(patient_id)

    # All medical records for the patient
    medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()

    # All appointments for the patient with doctor info
    DoctorUser = aliased(User)
    appts = db.session.query(Appointment, Doctor, DoctorUser).join(Doctor, Appointment.doctor_id == Doctor.id).join(DoctorUser, Doctor.user_id == DoctorUser.id).filter(Appointment.patient_id == patient.id).order_by(Appointment.appointment_date.desc()).all()

    # Communications across all appointments for this patient
    comms = Communication.query.join(Appointment, Communication.appointment_id == Appointment.id).filter(Appointment.patient_id == patient.id).order_by(Communication.timestamp.desc()).all()

    # Files uploaded by doctors or patient (from medical_records) are in medical_records.file_path
    return render_template('admin/patient_detail.html',
                           patient=patient,
                           medical_records=medical_records,
                           appointments=appts,
                           communications=comms)


# Doctor view for a specific patient's medical records
@app.route('/doctor/patient/<int:patient_id>/medical-records')
@login_required
def doctor_patient_medical_records(patient_id):
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    doctor = Doctor.query.filter_by(user_id=current_user.id).first_or_404()
    patient = Patient.query.options(joinedload(Patient.user)).get_or_404(patient_id)

    # Optional: verify that doctor has seen this patient before or allow access
    medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()

    return render_template('doctor/patient_medical_records.html', doctor=doctor, patient=patient, medical_records=medical_records)


# Patient view for their own medical records
@app.route('/patient/medical-records')
@login_required
def patient_medical_records():
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    patient = Patient.query.filter_by(user_id=current_user.id).first_or_404()
    medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()
    return render_template('patient/medical_records.html', patient=patient, medical_records=medical_records)


# API to add a medical record (doctor or patient)
@app.route('/api/medical_record/add', methods=['POST'])
@login_required
@csrf.exempt
def api_add_medical_record():
    # allowed for doctors and patients
    if current_user.role not in ('doctor', 'patient', 'admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    # multipart/form-data expected
    patient_id = request.form.get('patient_id')
    record_type = request.form.get('record_type') or request.form.get('type') or 'general'
    description = request.form.get('description')
    file = request.files.get('file')

    if not patient_id:
        return jsonify({'success': False, 'error': 'patient_id required'}), 400

    patient = db.session.get(Patient, patient_id)
    if not patient:
        return jsonify({'success': False, 'error': 'Patient not found'}), 404

    # If current_user is patient ensure they are adding to their own record
    if current_user.role == 'patient' and patient.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    # Save file if provided
    rel_path = None
    if file and allowed_file(file.filename):
        rel_path = handle_file_upload(current_user, file, upload_type='medical_records', encrypt=True)

    mr = MedicalRecord(patient_id=patient.id, record_type=record_type, created_by=current_user.id)
    if rel_path:
        mr.file_path = rel_path
    if description:
        mr.description = description

    db.session.add(mr)
    db.session.commit()

    # Optionally emit socket event to notify patient/doctor
    return jsonify({'success': True, 'medical_record_id': mr.id})


@app.route('/api/medical_record/<int:record_id>', methods=['GET'])
@login_required
def api_get_medical_record(record_id):
    """Return medical record details as JSON for editing."""
    mr = MedicalRecord.query.get_or_404(record_id)
    # Permission: allow admin, doctor (if assigned/creator), or the patient owner
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or mr.patient_id != patient.id:
            return jsonify({'error': 'Access denied'}), 403
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        patient = db.session.get(Patient, mr.patient_id)
        allowed = False
        if mr.created_by == current_user.id:
            allowed = True
        if doctor and Appointment.query.filter_by(doctor_id=doctor.id, patient_id=patient.id).count() > 0:
            allowed = True
        if not allowed:
            return jsonify({'error': 'Access denied'}), 403
    elif current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    return jsonify({
        'id': mr.id,
        'patient_id': mr.patient_id,
        'record_type': mr.record_type,
        'description': mr.description,
        'has_file': bool(mr.file_path),
        'created_by': mr.created_by,
        'created_at': mr.created_at.isoformat() if mr.created_at else None
    })


# API to update a medical record (description or replace file)
@app.route('/api/medical_record/<int:record_id>/update', methods=['POST'])
@login_required
@csrf.exempt
def api_update_medical_record(record_id):
    mr = MedicalRecord.query.get_or_404(record_id)

    # Only creator, doctor, or admin can update
    if current_user.role not in ('admin', 'doctor') and mr.created_by != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    description = request.form.get('description')
    file = request.files.get('file')

    if description is not None:
        mr.description = description

    if file and allowed_file(file.filename):
        rel_path = handle_file_upload(current_user, file, upload_type='medical_records', encrypt=True)
        if rel_path:
            mr.file_path = rel_path

    db.session.add(mr)
    db.session.commit()
    return jsonify({'success': True})


# API to delete a medical record
@app.route('/api/medical_record/<int:record_id>/delete', methods=['POST'])
@login_required
@csrf.exempt
def api_delete_medical_record(record_id):
    mr = MedicalRecord.query.get_or_404(record_id)
    if current_user.role not in ('admin', 'doctor') and mr.created_by != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    try:
        db.session.delete(mr)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/medical_records/patient/<int:patient_id>', methods=['GET'])
@login_required
def api_get_medical_records_for_patient(patient_id):
    """Return medical records for a patient as JSON. Accessible to patient owner, doctor (if linked), or admin."""
    patient = db.session.get(Patient, patient_id)
    if not patient:
        return jsonify({'error': 'Patient not found'}), 404

    # Authorization
    if current_user.role == 'patient':
        p = Patient.query.filter_by(user_id=current_user.id).first()
        if not p or p.id != patient.id:
            return jsonify({'error': 'Access denied'}), 403
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor:
            return jsonify({'error': 'Doctor profile not found'}), 403
        # ensure doctor has appointments with patient (or allow admin/creator later)
        if Appointment.query.filter_by(doctor_id=doctor.id, patient_id=patient.id).count() == 0:
            return jsonify({'error': 'Access denied'}), 403
    elif current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()
    out = []
    for r in records:
        out.append({
            'id': r.id,
            'record_type': r.record_type,
            'description': r.description,
            'has_file': bool(r.file_path),
            'created_by': r.created_by,
            'created_at': r.created_at.isoformat() if r.created_at else None
        })
    return jsonify({'medical_records': out, 'total': len(out)})

# Duplicate Socket.IO handler removed. The consolidated, non-blocking
# `save_recording` handler is defined earlier in this file and uses a
# background task to perform encryption and DB commits to avoid blocking
# the Socket.IO event loop.


# Profile picture upload (users can upload their own; admin may upload for others)
@app.route('/upload_profile_picture', methods=['POST'])
@login_required
@csrf.exempt
def upload_profile_picture():
    """Upload and encrypt user profile picture, storing in BLOB and with proper directory structure."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Empty filename'}), 400
    
    # Determine target user
    target_user = current_user
    if current_user.role == 'admin' and request.form.get('user_id'):
        try:
            uid = int(request.form.get('user_id'))
            target_user = db.session.get(User, uid) or target_user
        except Exception:
            pass
    
    if file and allowed_file(file.filename):
        # Read file
        raw = file.read()
        try:
            # Encrypt file bytes
            encrypted_bytes = encrypt_file_bytes(raw)
            
            # Store encrypted bytes in BLOB column
            target_user.profile_picture_blob = encrypted_bytes
            target_user.profile_picture_mime = file.content_type or 'image/jpeg'
            target_user.profile_picture_name = secure_filename(file.filename)
            
            # Also save to filesystem for reference (uploads/user/{role}/profile_pictures/)
            try:
                rel_root = _uploads_rel_root() or 'uploads'
                user_role = getattr(target_user, 'role', 'user')
                user_id = getattr(target_user, 'id', 'unknown')
                
                # Create directory structure: uploads/user/{role}/profile_pictures/
                rel_dir = os.path.join(rel_root, 'user', user_role, 'profile_pictures').replace('\\', '/')
                full_dir = os.path.join(app.root_path, rel_dir)
                os.makedirs(full_dir, exist_ok=True)
                
                # Generate unique filename
                storage_name = f"{uuid4().hex}__{secure_filename(file.filename)}.enc"
                full_path = os.path.join(full_dir, storage_name)
                rel_path_for_db = os.path.join(rel_dir, storage_name).replace('\\', '/')
                
                # Save encrypted file to disk
                with open(full_path, 'wb') as fh:
                    fh.write(encrypted_bytes)
                
                # Store the file path as backup (encrypted)
                target_user.profile_picture = rel_path_for_db
            except Exception as file_err:
                logging.warning(f"Could not save profile picture to filesystem: {file_err}")
                # Continue anyway since BLOB is stored
            
            db.session.add(target_user)
            db.session.commit()
            
            return jsonify({
                'success': True, 
                'user_id': target_user.id,
                'message': 'Profile picture uploaded successfully'
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error uploading profile picture: {e}")
            return jsonify({'success': False, 'error': 'Upload failed', 'detail': str(e)}), 500
    
    return jsonify({'success': False, 'error': 'Invalid file type'}), 400


# Serve decrypted profile picture for a user
@app.route('/profile_picture/<int:user_id>')
def profile_picture(user_id):
    """Serve encrypted profile picture from BLOB or file path, or fallback to SVG avatar."""
    try:
        user = db.session.get(User, user_id)
        if not user:
            return _get_default_avatar('U')
        
        # First priority: Check for BLOB in database (encrypted)
        if user.profile_picture_blob:
            try:
                raw_bytes = decrypt_file_bytes(user.profile_picture_blob)
                if raw_bytes:
                    # Use stored MIME type or guess from filename
                    mime_type = user.profile_picture_mime or 'image/jpeg'
                    return send_file(
                        BytesIO(raw_bytes),
                        mimetype=mime_type
                    )
            except Exception as dec_err:
                logging.error(f"Decryption error for profile blob (user {user_id}): {dec_err}")
        
        # Second priority: Check for file path (encrypted path in DB or external URL)
        pic_path = user.profile_picture
        
        if pic_path:
            # Check if it's an external URL (from OAuth, e.g., Google/Facebook)
            if pic_path.startswith('http'):
                return redirect(pic_path)
            
            # Check if it's a blob marker
            if pic_path.startswith('blob://'):
                # BLOB already checked above, this shouldn't happen
                pass
            else:
                # It's a local encrypted file path stored in DB
                try:
                    full_path = os.path.join(app.root_path, pic_path)
                    if os.path.exists(full_path) and os.path.isfile(full_path):
                        # Decrypt and serve file
                        with open(full_path, 'rb') as fh:
                            encrypted_bytes = fh.read()
                        try:
                            raw_bytes = decrypt_file_bytes(encrypted_bytes)
                            if raw_bytes:
                                # Guess content type from file extension
                                _, ext = os.path.splitext(pic_path)
                                content_type = 'image/jpeg'
                                if ext.lower() in ['.png']:
                                    content_type = 'image/png'
                                elif ext.lower() in ['.gif']:
                                    content_type = 'image/gif'
                                elif ext.lower() in ['.webp']:
                                    content_type = 'image/webp'
                                return send_file(
                                    BytesIO(raw_bytes),
                                    mimetype=content_type
                                )
                        except Exception as dec_err:
                            logging.error(f"Decryption error for {pic_path}: {dec_err}")
                except Exception as file_err:
                    logging.error(f"File access error for {pic_path}: {file_err}")
        
        # Fallback to SVG avatar with user initials
        return _get_default_avatar(user.get_initials())
        
    except Exception as e:
        logging.error(f"Error serving profile picture for user {user_id}: {e}")
        return _get_default_avatar('E')


def _get_default_avatar(initials='U'):
    """Generate and return a default SVG avatar with given initials."""
    # Use a color based on initial hash for visual variety
    color_map = {
        'A': '#FF6B6B', 'B': '#4ECDC4', 'C': '#45B7D1', 'D': '#FFA07A',
        'E': '#98D8C8', 'F': '#F7DC6F', 'G': '#BB8FCE', 'H': '#85C1E2',
        'I': '#F8B88B', 'J': '#ABEBC6', 'K': '#F5B7B1', 'L': '#D7BDE2',
        'M': '#A9DFBF', 'N': '#F9E79F', 'O': '#AED6F1', 'P': '#F1948A',
        'Q': '#D5F4E6', 'R': '#FADBD8', 'S': '#E8DAEF', 'T': '#A3E4D7',
        'U': '#667eea', 'V': '#764EA2', 'W': '#F093FB', 'X': '#4158D0',
        'Y': '#C471ED', 'Z': '#12C2E9'
    }
    color = color_map.get(initials[0].upper(), '#667eea')
    return f'''
    <svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <circle cx="50" cy="50" r="50" fill="{color}"/>
        <text x="50" y="60" text-anchor="middle" fill="white" font-size="40" font-weight="bold" font-family="Arial">{initials}</text>
    </svg>
    ''', 200, {'Content-Type': 'image/svg+xml'}


def get_user_profile_picture_url(user):
    """
    Get the profile picture URL for a user for use in JSON responses.
    Returns: URL string or None
    """
    if not user:
        return None
    
    # If user has profile picture (BLOB or path), use the route
    if user.profile_picture:
        if isinstance(user.profile_picture, str) and user.profile_picture.startswith('http'):
            # External URL (OAuth)
            return user.profile_picture
        else:
            # Local BLOB or encrypted file path
            return url_for('profile_picture', user_id=user.id, _external=False)
    
    return None


def get_user_profile_picture_url(user):
    """Get profile picture URL for a user, handling BLOBs and paths."""
    if not user:
        return url_for('profile_picture', user_id=0, _external=True)
    
    # Check if user has BLOB or path
    if user.profile_picture_blob or user.profile_picture:
        return url_for('profile_picture', user_id=user.id, _external=True)
    
    # No profile picture, will fallback to SVG avatar
    return url_for('profile_picture', user_id=user.id, _external=True)


@app.route('/api/user/<int:user_id>/set-availability', methods=['POST'])
@login_required
@csrf.exempt
def api_set_user_availability(user_id):
    """Set a simple availability flag for the current user (used by the communication UI).
    This updates `show_availability` for doctors and will also allow patients to toggle a lightweight presence flag.
    """
    if current_user.id != user_id and current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    data = request.get_json() or {}
    avail = data.get('available')
    if avail is None:
        return jsonify({'success': False, 'error': 'available boolean required'}), 400

    try:
        # For doctors we persist show_availability; for other users we reuse same column if present
        try:
            current_user.show_availability = bool(avail)
        except Exception:
            # Fallback: try to set attribute anyway
            setattr(current_user, 'show_availability', bool(avail))

        db.session.add(current_user)
        db.session.commit()

        # Emit socket event to notify presence change (best-effort)
        try:
            if SOCKETIO_AVAILABLE:
                socketio.emit('user_availability_changed', {'user_id': current_user.id, 'available': bool(avail)})
        except Exception:
            pass

        return jsonify({'success': True, 'available': bool(avail)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

    
# Admin Communication Dashboard
@app.route('/admin/communication')
@login_required
def admin_communication():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Get all communications for admin view
    communications = db.session.query(
        Communication,
        Appointment,
        User,
        Patient,
        Doctor
    ).join(
        Appointment, Communication.appointment_id == Appointment.id
    ).join(
        User, Communication.sender_id == User.id
    ).join(
        Patient, Appointment.patient_id == Patient.id
    ).join(
        Doctor, Appointment.doctor_id == Doctor.id
    ).order_by(Communication.timestamp.desc()).all()

    # Get appointments for sidebar and compute per-appointment unread counts
    raw_appointments = db.session.query(
        Appointment
    ).join(
        Patient
    ).join(
        Doctor
    ).order_by(Appointment.appointment_date.desc()).all()

    appointments = []
    for apt in raw_appointments:
        try:
            unread_count = Communication.query.filter_by(appointment_id=apt.id, is_read=False).count()
        except Exception:
            unread_count = 0
        appointments.append({'appointment': apt, 'unread_count': unread_count})

    # Dashboard statistics derived from DB
    try:
        total_messages = Communication.query.count()
    except Exception:
        total_messages = len(communications)

    try:
        video_calls = Appointment.query.filter(Appointment.consultation_type == 'video').count()
    except Exception:
        video_calls = 0

    try:
        voice_calls = Appointment.query.filter(Appointment.consultation_type == 'voice').count()
    except Exception:
        voice_calls = 0

    try:
        documents_shared = Communication.query.filter(Communication.message_type == 'document').count() + MedicalRecord.query.count()
    except Exception:
        documents_shared = 0

    return render_template('admin/communication.html',
                         communications=communications,
                         appointments=appointments,
                         stats={
                             'total_messages': total_messages,
                             'video_calls': video_calls,
                             'voice_calls': voice_calls,
                             'documents_shared': documents_shared
                         },
                         iceServers=app.config.get('ICE_SERVERS', []))

from models import Report

@app.route('/doctor/reports', methods=['GET'])
@login_required
def get_doctor_reports():
    if current_user.role != 'doctor':
        return jsonify({'error': 'Unauthorized'}), 403
    reports = Report.query.filter_by(doctor_id=current_user.doctor_profile.id).order_by(Report.created_at.desc()).all()
    data = [
        {
            'id': r.id,
            'title': r.title,
            'description': r.description,
            'created_at': r.created_at.strftime('%Y-%m-%d %H:%M') if r.created_at else ''
        }
        for r in reports
    ]
    return jsonify(data)

@app.route('/doctor/emergency_call', methods=['POST'])
@login_required
def doctor_emergency_call():
    if current_user.role != 'doctor':
        return jsonify({'error': 'Unauthorized'}), 403
    # Here you can implement logic to notify admins, send SMS, or log the emergency event
    # For now, just log the call and return success
    from datetime import datetime
    # Example: log to AuditLog
    log = AuditLog(
        user_id=current_user.id,
        action='emergency_call',
        description=f'Doctor {current_user.get_display_name()} triggered an emergency call.',
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Emergency call logged and admins notified.'})

# Doctor Communication Dashboard
@app.route('/doctor/communication')
@login_required
def doctor_communication():
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    # Get doctor's appointments with communications
    appointments = db.session.query(
        Appointment
    ).filter(
        Appointment.doctor_id == doctor.id
    ).join(
        Patient
    ).join(
        User, Patient.user_id == User.id
    ).order_by(Appointment.appointment_date.desc()).all()
    
    return render_template('doctor/communication.html',
                         appointments=appointments,
                         doctor=doctor,
                         iceServers=app.config.get('ICE_SERVERS', []))

# Patient Communication Dashboard
@app.route('/patient/communication')
@login_required
def patient_communication():
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    
    # Get patient's appointments with communications
    appointments = db.session.query(
        Appointment
    ).filter(
        Appointment.patient_id == patient.id
    ).join(
        Doctor
    ).join(
        User, Doctor.user_id == User.id
    ).order_by(Appointment.appointment_date.desc()).all()
    
    return render_template('patient/communication.html',
                         appointments=appointments,
                         patient=patient,
                         iceServers=app.config.get('ICE_SERVERS', []))

# Universal communication handler for specific appointment
@app.route('/communication/appointment/<int:appointment_id>')
@login_required
def communication_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Check access permissions
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            flash('Access denied', 'error')
            return redirect(url_for('patient_communication'))
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if appointment.doctor_id != doctor.id:
            flash('Access denied', 'error')
            return redirect(url_for('doctor_communication'))
    # Admin has access to all communications
    
    messages = Communication.query.filter_by(
        appointment_id=appointment_id
    ).order_by(Communication.timestamp).all()
    
    # Mark messages as read for the current user
    for message in messages:
        if message.sender_id != current_user.id and not message.is_read:
            message.is_read = True
    db.session.commit()
    
    return render_template('communication/communication_dashboard.html',
                         appointment=appointment,
                         messages=messages)


# ==========================
# Testimonials
# ==========================
@app.route('/api/testimonial', methods=['POST'])
@login_required
@csrf.exempt
def submit_testimonial_api():
    """Submit a testimonial at the end of a consultation (patient only)."""
    if current_user.role != 'patient':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    data = request.get_json() or request.form
    appointment_id = data.get('appointment_id')
    rating = data.get('rating')
    content = data.get('content', '').strip()

    if not appointment_id or rating is None:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    try:
        rating = int(rating)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid rating'}), 400

    if rating < 1 or rating > 5:
        return jsonify({'success': False, 'error': 'Rating must be between 1 and 5'}), 400

    appointment = Appointment.query.get_or_404(appointment_id)
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient or appointment.patient_id != patient.id:
        return jsonify({'success': False, 'error': 'Access denied for this appointment'}), 403

    # Create testimonial
    testimonial = Testimonial(
        patient_id=patient.id,
        doctor_id=appointment.doctor_id,
        appointment_id=appointment.id,
        rating=rating,
    )
    testimonial.content = content

    db.session.add(testimonial)
    db.session.commit()

    # Return new average rating for the doctor
    doctor = db.session.get(Doctor, testimonial.doctor_id)
    avg = doctor.average_rating if doctor else None

    return jsonify({'success': True, 'testimonial_id': testimonial.id, 'doctor_average': avg}), 201


@app.route('/api/appointments/<int:appointment_id>/testimonial', methods=['POST'])
@login_required
@csrf.exempt
def submit_testimonial_for_appointment(appointment_id):
    """Submit a testimonial for a specific appointment (patient only).
    This endpoint mirrors `/api/testimonial` but uses the appointment_id path parameter
    because some client code posts to `/api/appointments/<id>/testimonial`.
    """
    if current_user.role != 'patient':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    data = request.get_json() or request.form
    rating = data.get('rating')
    content = data.get('content', '').strip()

    if rating is None:
        return jsonify({'success': False, 'error': 'Missing rating'}), 400

    try:
        rating = int(rating)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid rating'}), 400

    if rating < 1 or rating > 5:
        return jsonify({'success': False, 'error': 'Rating must be between 1 and 5'}), 400

    appointment = Appointment.query.get_or_404(appointment_id)
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient or appointment.patient_id != patient.id:
        return jsonify({'success': False, 'error': 'Access denied for this appointment'}), 403

    # Create testimonial
    testimonial = Testimonial(
        patient_id=patient.id,
        doctor_id=appointment.doctor_id,
        appointment_id=appointment.id,
        rating=rating,
    )
    testimonial.content = content

    db.session.add(testimonial)
    db.session.commit()

    doctor = db.session.get(Doctor, testimonial.doctor_id)
    avg = doctor.average_rating if doctor else None

    return jsonify({'success': True, 'testimonial_id': testimonial.id, 'doctor_average': avg}), 201


@app.route('/appointments/<int:appointment_id>/testimonial', methods=['GET'])
@login_required
def show_testimonial_form(appointment_id):
    """Render a simple testimonial submission page for patients after a call."""
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    appointment = Appointment.query.get_or_404(appointment_id)
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient or appointment.patient_id != patient.id:
        flash('Access denied for this appointment', 'error')
        return redirect(url_for('patient_dashboard'))

    doctor = db.session.get(Doctor, appointment.doctor_id)
    return render_template('patient/submit_testimonial.html', appointment=appointment, doctor=doctor)


# Dedicated testimonials listing (system-wide and per-doctor)
@app.route('/testimonials')
def testimonials_page():
    # Prepare doctors list for client-side filter (public subset)
    doctors = []
    try:
        docs = db.session.query(Doctor, User).join(User, Doctor.user_id == User.id).all()
        for d, u in docs:
            doctors.append({'id': d.id, 'name': u.get_display_name()})
    except Exception:
        doctors = []

    selected = request.args.get('doctor_id')
    return render_template('testimonials.html', doctors=doctors, selected_doctor=selected)


@app.route('/doctors/<int:doctor_id>/testimonials')
def doctor_testimonials_page(doctor_id):
    # Reuse the testimonials page but pre-select the doctor
    doctors = []
    try:
        docs = db.session.query(Doctor, User).join(User, Doctor.user_id == User.id).all()
        for d, u in docs:
            doctors.append({'id': d.id, 'name': u.get_display_name()})
    except Exception:
        doctors = []

    return render_template('testimonials.html', doctors=doctors, selected_doctor=str(doctor_id))


@app.route('/api/testimonials')
def get_testimonials():
    """Return recent public testimonials for display with profile pictures."""
    # Pagination and sorting
    try:
        page = int(request.args.get('page', 1))
    except Exception:
        page = 1
    try:
        per_page = int(request.args.get('per_page', 10))
    except Exception:
        per_page = 10

    sort_by = request.args.get('sort_by', 'created_at')  # or 'rating'
    doctor_filter = request.args.get('doctor_id')

    q = Testimonial.query.filter_by(is_public=True)
    if doctor_filter:
        try:
            q = q.filter(Testimonial.doctor_id == int(doctor_filter))
        except Exception:
            pass

    # Sorting
    if sort_by == 'rating':
        q = q.order_by(Testimonial.rating.desc(), Testimonial.created_at.desc())
    else:
        q = q.order_by(Testimonial.created_at.desc())

    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()

    out = []
    for t in items:
        try:
            patient_name = t.patient.user.get_display_name() if t.patient and t.patient.user else None
            patient_id = t.patient.user.id if t.patient and t.patient.user else None
        except Exception:
            patient_name = None
            patient_id = None
        try:
            doctor_user = t.doctor.user if t.doctor and getattr(t.doctor, 'user', None) else None
            doctor_name = doctor_user.get_display_name() if doctor_user else None
            doctor_id = doctor_user.id if doctor_user else None
        except Exception:
            doctor_name = None
            doctor_id = None

        out.append({
            'id': t.id,
            'patient_name': patient_name,
            'patient_id': patient_id,
            'doctor_name': doctor_name,
            'doctor_id': t.doctor_id,
            'rating': t.rating,
            'content': t.content,
            'created_at': t.created_at.isoformat()
        })

    # Compute doctor average if filtered
    doctor_avg = None
    if doctor_filter:
        try:
            doctor_avg = db.session.query(func.avg(Testimonial.rating)).filter(Testimonial.doctor_id == int(doctor_filter), Testimonial.is_public == True).scalar()
            if doctor_avg is not None:
                doctor_avg = round(float(doctor_avg), 2)
        except Exception:
            doctor_avg = None

    return jsonify({
        'testimonials': out,
        'total': total,
        'page': page,
        'per_page': per_page,
        'doctor_average': doctor_avg
    })


@app.route('/api/doctors/<int:doctor_id>/profile-with-reviews')
def get_doctor_profile_with_reviews(doctor_id):
    """Get doctor profile with testimonials and average rating (public)."""
    try:
        doctor = db.session.get(Doctor, doctor_id)
        if not doctor:
            return jsonify({'error': 'Doctor not found'}), 404
        
        user = doctor.user
        
        # Get testimonials for this doctor
        testimonials = Testimonial.query.filter_by(doctor_id=doctor_id, is_public=True).order_by(
            Testimonial.created_at.desc()
        ).limit(10).all()
        
        # Calculate average rating
        avg_rating = db.session.query(func.avg(Testimonial.rating)).filter(
            Testimonial.doctor_id == doctor_id,
            Testimonial.is_public == True
        ).scalar()
        avg_rating = round(float(avg_rating), 2) if avg_rating else 0
        
        # Build testimonials list
        testimonials_list = []
        for t in testimonials:
            try:
                patient_name = t.patient.user.get_display_name() if t.patient and t.patient.user else "Anonymous"
                patient_id = t.patient.user.id if t.patient and t.patient.user else None
            except:
                patient_name = "Anonymous"
                patient_id = None
            
            testimonials_list.append({
                'id': t.id,
                'patient_name': patient_name,
                'patient_id': patient_id,
                'rating': t.rating,
                'content': t.content,
                'created_at': t.created_at.isoformat()
            })
        
        return jsonify({
            'doctor': {
                'id': doctor.id,
                'name': user.get_display_name() if user else "Unknown",
                'specialization': doctor.specialization,
                'bio': doctor.bio,
                'experience_years': doctor.experience_years,
                'qualifications': doctor.qualifications,
                'average_rating': avg_rating,
                'testimonials_count': len(testimonials),
                'testimonials': testimonials_list
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/call_logs')
@login_required
def get_call_logs():
    """Return call history for current user. Admins receive all logs."""
    try:
        filter_by = request.args.get('filter', 'all')
        page = int(request.args.get('page', 1)) if request.args.get('page') else 1
        per_page = int(request.args.get('per_page', 25)) if request.args.get('per_page') else 25
    except Exception:
        page, per_page = 1, 25

    q = CallHistory.query

    # Non-admins see only calls they participated in
    if current_user.role != 'admin':
        q = q.filter((CallHistory.caller_id == current_user.id) | (CallHistory.callee_id == current_user.id))

    # Apply simple filter
    if filter_by == 'incoming':
        q = q.filter(CallHistory.callee_id == current_user.id)
    elif filter_by == 'outgoing':
        q = q.filter(CallHistory.caller_id == current_user.id)
    elif filter_by == 'missed':
        q = q.filter((CallHistory.end_reason == 'missed') | (CallHistory.end_reason == 'unanswered'))
    elif filter_by == 'declined':
        q = q.filter(CallHistory.end_reason == 'callee_declined')

    total = q.count()
    items = q.order_by(CallHistory.initiated_at.desc()).offset((page-1)*per_page).limit(per_page).all()

    out = [c.to_dict() for c in items]

    return jsonify({
        'call_logs': out,
        'total': total,
        'page': page,
        'per_page': per_page
    })

# API to get messages for an appointment
@app.route('/api/messages/<int:appointment_id>')
@login_required
def get_messages(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if not verify_appointment_access(appointment, current_user):
        return jsonify({'error': 'Access denied'}), 403
    
    messages = Communication.query.filter_by(
        appointment_id=appointment.id
    ).order_by(Communication.timestamp).all()
    
    messages_data = []
    for msg in messages:
        sender_name = safe_display_name(msg.sender)
        messages_data.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'sender_name': sender_name,
            'message_type': msg.message_type,
            'content': msg.content,
            'file_path': msg.file_path,
            'timestamp': msg.timestamp.isoformat(),
            'is_read': msg.is_read,
            'is_sent': True if msg.sender_id == current_user.id else False
        })

    # Return appointment id so client can send messages using it
    return jsonify({
        'appointment_id': appointment.id,
        'messages': messages_data
    })

# File upload endpoint
@app.route('/api/upload-file', methods=['POST'])
@login_required
@csrf.exempt
def upload_file_api():
    """Upload a file and return its URL"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    appointment_id = request.form.get('appointment_id')
    
    if not appointment_id:
        return jsonify({'success': False, 'error': 'No appointment specified'}), 400
    
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if not verify_appointment_access(appointment, current_user):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        storage_name = f"{uuid4().hex}__{filename}.enc"
        
        # Determine upload directory based on appointment
        rel_root = _uploads_rel_root() or 'uploads'
        rel_dir = os.path.join(rel_root, 'appointments', str(appointment_id), 'files').replace('\\', '/')
        full_dir = os.path.join(app.root_path, rel_dir)
        os.makedirs(full_dir, exist_ok=True)
        
        full_path = os.path.join(full_dir, storage_name)
        rel_path_for_db = os.path.join(rel_dir, storage_name).replace('\\', '/')
        
        # Read and encrypt file
        raw = file.read()
        try:
            encrypted_bytes = encrypt_file_bytes(raw)
            with open(full_path, 'wb') as fh:
                fh.write(encrypted_bytes)
            
            # Determine message type based on file content type or extension
            message_type = 'document'
            if file.content_type.startswith('image/'):
                message_type = 'image'
            elif file.content_type.startswith('audio/') or filename.endswith(('.webm', '.wav', '.mp3', '.m4a')):
                message_type = 'audio'
            
            # Create communication record
            comm = Communication(
                appointment_id=appointment_id,
                sender_id=current_user.id,
                message_type=message_type,
                content=filename,
                file_path=rel_path_for_db,
                message_status='sent',
                is_read=False
            )
            db.session.add(comm)
            db.session.commit()
            
            # BROADCAST via Socket.IO immediately for real-time delivery
            if SOCKETIO_AVAILABLE:
                appointment_room = f'appointment_{appointment_id}'
                file_url = url_for('download_communication_file', communication_id=comm.id, _external=True)
                
                message_data = {
                    'id': comm.id,
                    'appointment_id': appointment_id,
                    'sender_id': current_user.id,
                    'sender_name': safe_display_name(current_user),
                    'message_type': message_type,
                    'content': filename,
                    'file_url': file_url,
                    'file_name': filename,
                    'file_size': len(raw),
                    'timestamp': comm.timestamp.isoformat(),
                    'message_status': 'sent',
                    'is_sent': True,
                    'is_read': False
                }
                socketio.emit('message_received', message_data, room=appointment_room)
                
                # Check if recipient is online for delivery status
                recipient_id = None
                if current_user.role == 'patient':
                    doctor = db.session.get(Doctor, appointment.doctor_id)
                    recipient_id = doctor.user_id if doctor else None
                else:
                    patient = db.session.get(Patient, appointment.patient_id)
                    recipient_id = patient.user_id if patient else None
                
                if recipient_id and recipient_id in user_sockets:
                    comm.message_status = 'delivered'
                    db.session.commit()
                    socketio.emit('message_status_updated', {
                        'message_id': comm.id,
                        'status': 'delivered',
                        'appointment_id': appointment_id
                    }, room=appointment_room)
            
            return jsonify({
                'success': True,
                'file_url': file_url,
                'filename': filename,
                'file_size': len(raw),
                'message_id': comm.id,
                'message_type': message_type
            })

        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    return jsonify({'success': False, 'error': 'Invalid file type'}), 400

# Helper function to verify appointment access
def verify_appointment_access(appointment, user):
    if user.role == 'admin':
        return True
    elif user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=user.id).first()
        return appointment.doctor_id == doctor.id
    elif user.role == 'patient':
        patient = Patient.query.filter_by(user_id=user.id).first()
        return appointment.patient_id == patient.id
    return False

# Update the send_message function to handle file uploads
@app.route('/api/send_message', methods=['POST'])
@login_required
@csrf.exempt
def send_message():
    data = request.get_json()
    appointment_id = data.get('appointment_id')
    message = data.get('message')
    message_type = data.get('type', 'text')
    file_path = data.get('file_path')
    
    appointment = Appointment.query.get_or_404(appointment_id)
    
    if not verify_appointment_access(appointment, current_user):
        return jsonify({'error': 'Access denied'}), 403
    
    communication = Communication(
        appointment_id=appointment_id,
        sender_id=current_user.id,
        message_type=message_type,
        content=message,
        file_path=file_path
    )
    
    db.session.add(communication)
    db.session.commit()
    # Create a notification for the recipient
    try:
        recipient_id = None
        if current_user.role == 'patient':
            doctor = db.session.get(Doctor, appointment.doctor_id)
            recipient_id = doctor.user_id if doctor else None
        else:
            patient = db.session.get(Patient, appointment.patient_id)
            recipient_id = patient.user_id if patient else None

        if recipient_id:
            notif = Notification(
                user_id=recipient_id,
                appointment_id=appointment_id,
                notification_type='message',
                sender_id=current_user.id,
                title='New message',
                body=(message[:240] if message else 'You have a new message'),
                is_read=False
            )
            db.session.add(notif)
            db.session.commit()

        # Broadcast via Socket.IO for real-time delivery
        if SOCKETIO_AVAILABLE:
            appointment_room = f'appointment_{appointment_id}'
            message_data = {
                'id': communication.id,
                'appointment_id': appointment_id,
                'sender_id': current_user.id,
                'sender_name': safe_display_name(current_user),
                'message_type': message_type,
                'content': message,
                'file_path': file_path,
                'timestamp': communication.timestamp.isoformat(),
                'message_status': 'sent',
                'is_sent': True,
                'is_read': False
            }
            socketio.emit('message_received', message_data, room=appointment_room)

            # If recipient is online, mark delivered and emit status update
            if recipient_id and recipient_id in user_sockets:
                communication.message_status = 'delivered'
                db.session.commit()
                socketio.emit('message_status_updated', {
                    'message_id': communication.id,
                    'status': 'delivered',
                    'appointment_id': appointment_id
                }, room=appointment_room)

    except Exception as e:
        app.logger.exception('Failed to create notification or emit message: %s', e)

    return jsonify({'success': True, 'message_id': communication.id})


# Endpoint to download communication file (decrypt and stream)
@app.route('/download/communication/<int:communication_id>')
@login_required
def download_communication_file(communication_id):
    comm = Communication.query.get_or_404(communication_id)
    appointment = db.session.get(Appointment, comm.appointment_id)
    if not verify_appointment_access(appointment, current_user):
        return abort(403)

    stored_path = comm.file_path
    full_path = resolve_stored_path(stored_path)
    if not full_path or not os.path.exists(full_path):
        return abort(404)

    # Parse original filename from storage name (uuid__orig.ext.enc)
    base = os.path.basename(stored_path)
    orig_name = base
    if '__' in base:
        orig_part = base.split('__', 1)[1]
        if orig_part.endswith('.enc'):
            orig_name = orig_part[:-4]

    try:
        with open(full_path, 'rb') as fh:
            encrypted_bytes = fh.read()
        decrypted = decrypt_file_bytes(encrypted_bytes)
    except Exception as e:
        return abort(500)

    bio = BytesIO(decrypted)
    bio.seek(0)
    try:
        return send_file(bio, as_attachment=True, download_name=orig_name, mimetype='application/octet-stream')
    except TypeError:
        # Fallback for older Flask versions
        return send_file(bio, as_attachment=True, attachment_filename=orig_name, mimetype='application/octet-stream')


# Endpoint to download medical record file (decrypt and stream)
@app.route('/download/medical_record/<int:record_id>')
@login_required
def download_medical_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    # Only allow patient or doctor who owns/created or admin
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if record.patient_id != patient.id:
            return abort(403)
    elif current_user.role == 'doctor':
        # Allow if doctor created the record or if the doctor is the patient's doctor
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        patient = db.session.get(Patient, record.patient_id)
        allowed = False
        if record.created_by == current_user.id:
            allowed = True
        # If doctor is assigned to this patient via any appointment, allow access
        if doctor and Appointment.query.filter_by(doctor_id=doctor.id, patient_id=patient.id).count() > 0:
            allowed = True
        if not allowed:
            return abort(403)
    elif current_user.role != 'admin':
        return abort(403)

    stored_path = record.file_path
    full_path = resolve_stored_path(stored_path)
    if not full_path or not os.path.exists(full_path):
        return abort(404)

    base = os.path.basename(stored_path)
    orig_name = base
    if '__' in base:
        orig_part = base.split('__', 1)[1]
        if orig_part.endswith('.enc'):
            orig_name = orig_part[:-4]

    try:
        with open(full_path, 'rb') as fh:
            encrypted_bytes = fh.read()
        decrypted = decrypt_file_bytes(encrypted_bytes)
    except Exception:
        return abort(500)

    bio = BytesIO(decrypted)
    bio.seek(0)
    try:
        return send_file(bio, as_attachment=True, download_name=orig_name, mimetype='application/octet-stream')
    except TypeError:
        return send_file(bio, as_attachment=True, attachment_filename=orig_name, mimetype='application/octet-stream')


@app.route('/api/doctor/appointments')
@login_required
def get_doctor_appointments():
    """Get doctor's appointments grouped by patient with categorization: today, upcoming, completed, rescheduled, pending"""
    if current_user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404
    
    # Get appointments with patient info and payment status
    appointments = db.session.query(
        Appointment,
        Patient,
        User,
        Payment
    ).join(
        Patient, Appointment.patient_id == Patient.id
    ).join(
        User, Patient.user_id == User.id
    ).outerjoin(
        Payment, Appointment.id == Payment.appointment_id
    ).filter(
        Appointment.doctor_id == doctor.id
    ).order_by(Patient.id, Appointment.appointment_date.desc()).all()
    
    # Group appointments by patient and categorize
    patients_appointments = {}  # {patient_id: {'patient_info': ..., 'today': [...], 'upcoming': [...], etc}}
    
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    for appointment, patient, user, payment in appointments:
        patient_id = patient.id
        
        # Initialize patient group if not exists
        if patient_id not in patients_appointments:
            patients_appointments[patient_id] = {
                'patient': {
                    'id': patient.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'phone': user.phone,
                    'profile_picture_url': url_for('profile_picture', user_id=user.id, _external=True) if user else None
                },
                'today': [],
                'upcoming': [],
                'completed': [],
                'rescheduled': [],
                'pending': []
            }
        
        # Get last message for preview
        last_message = Communication.query.filter_by(
            appointment_id=appointment.id
        ).order_by(Communication.timestamp.desc()).first()
        
        # Determine payment status
        payment_status = 'pending'
        if payment:
            payment_status = payment.status
        elif appointment.status == 'completed':
            payment_status = 'completed'
        
        appointment_data = {
            'appointment_id': appointment.id,
            'appointment_date': appointment.appointment_date.isoformat(),
            'appointment_date_formatted': appointment.appointment_date.strftime('%d %b %Y'),
            'appointment_time': appointment.appointment_date.strftime('%H:%M'),
            'consultation_type': appointment.consultation_type,
            'status': appointment.status,
            'payment_status': payment_status,
            'last_message': last_message.content if last_message else 'No messages yet',
            'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
            'unread_count': Communication.query.filter_by(
                appointment_id=appointment.id,
                is_read=False
            ).filter(Communication.sender_id != current_user.id).count()
        }
        
        # Categorize appointment based on date and status
        appt_date = appointment.appointment_date
        # Ensure appointment datetime is timezone-aware for comparisons
        if appt_date is not None and appt_date.tzinfo is None:
            appt_date = appt_date.replace(tzinfo=timezone.utc)
        
        if appointment.status == 'completed':
            patients_appointments[patient_id]['completed'].append(appointment_data)
        elif appointment.status == 'rescheduled':
            patients_appointments[patient_id]['rescheduled'].append(appointment_data)
        elif appointment.status == 'pending' or (appointment.status not in ['confirmed', 'scheduled', 'completed', 'rescheduled', 'cancelled']):
            patients_appointments[patient_id]['pending'].append(appointment_data)
        elif appointment.status in ['confirmed', 'scheduled']:
            if today_start <= appt_date < today_end:
                patients_appointments[patient_id]['today'].append(appointment_data)
            elif appt_date >= today_end:
                patients_appointments[patient_id]['upcoming'].append(appointment_data)
            else:
                # Past appointments that aren't marked completed
                patients_appointments[patient_id]['completed'].append(appointment_data)
        elif appointment.status == 'cancelled':
            # Skip cancelled appointments
            pass
    
    # Convert to list format
    appointments_by_patient = list(patients_appointments.values())
    
    return jsonify({
        'appointments_by_patient': appointments_by_patient,
        'total_patients': len(patients_appointments)
    })

@app.route('/api/patient/doctors-with-appointments')
@login_required
def get_patient_doctors_with_appointments():
    """Get doctors with appointments for patient communication page"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    try:
        # Get all appointments with doctor info
        appointments = db.session.query(
            Appointment,
            Doctor,
            User
        ).join(
            Doctor, Appointment.doctor_id == Doctor.id
        ).join(
            User, Doctor.user_id == User.id
        ).filter(
            Appointment.patient_id == patient.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Group by doctor and get latest info
        doctors_map = {}
        for appointment, doctor, user in appointments:
            if doctor.id not in doctors_map:
                # Get last message for this doctor-patient
                last_message = Communication.query.filter_by(
                    appointment_id=appointment.id
                ).order_by(Communication.timestamp.desc()).first()
                
                # Get unread count
                unread_count = Communication.query.join(
                    Appointment, Communication.appointment_id == Appointment.id
                ).filter(
                    Appointment.patient_id == patient.id,
                    Appointment.doctor_id == doctor.id,
                    Communication.is_read == False,
                    Communication.sender_id != current_user.id
                ).count()
                
                # Get payment status
                payment = Payment.query.filter_by(
                    appointment_id=appointment.id
                ).order_by(Payment.created_at.desc()).first()
                
                # Check if doctor is online
                is_online = user.id in user_sockets if user else False
                
                doctors_map[doctor.id] = {
                    'id': doctor.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'specialization': doctor.specialization,
                    'profile_picture_url': url_for('profile_picture', user_id=user.id, _external=True) if user else None,
                    'is_online': is_online,
                    'last_message': last_message.content if last_message else None,
                    'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
                    'unread_count': unread_count,
                    'paymentStatus': payment.status if payment else 'pending'
                }
        
        return jsonify(list(doctors_map.values()))
        
    except Exception as e:
        print(f"Error in get_patient_doctors_with_appointments: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    

@app.route('/api/patient/appointments')
@login_required
def get_patient_appointments():
    """Get patient's appointments with doctor info and payment status"""
    try:
        if current_user.role != 'patient':
            return jsonify({'error': 'Access denied'}), 403
        
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        # Get appointments with doctor info and payment status - FIXED QUERY
        appointments = db.session.query(
            Appointment,
            Doctor,
            User
        ).join(
            Doctor, Appointment.doctor_id == Doctor.id
        ).join(
            User, Doctor.user_id == User.id
        ).filter(
            Appointment.patient_id == patient.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        appointments_data = []
        for appointment, doctor, user in appointments:
            # Get last message for preview
            last_message = Communication.query.filter_by(
                appointment_id=appointment.id
            ).order_by(Communication.timestamp.desc()).first()
            
            # Get payment status
            payment = Payment.query.filter_by(
                appointment_id=appointment.id
            ).order_by(Payment.created_at.desc()).first()
            
            payment_status = 'pending'
            if payment:
                payment_status = payment.status
            elif appointment.status == 'completed':
                payment_status = 'completed'
            
            # Check if doctor is online
            doctor_online = user.id in user_sockets if user else False
            
            appointments_data.append({
                'appointment_id': appointment.id,
                'doctor_id': doctor.id,
                'doctor': {
                    'id': doctor.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'specialization': doctor.specialization,
                    'is_online': doctor_online,
                    'profile_picture_url': url_for('profile_picture', user_id=user.id, _external=True) if user else None
                },
                'appointment_date': appointment.appointment_date.isoformat() if appointment.appointment_date else None,
                'appointment_time': appointment.appointment_date.strftime('%H:%M') if appointment.appointment_date else None,
                'consultation_type': appointment.consultation_type,
                'status': appointment.status,
                'payment_status': payment_status,
                'last_message': last_message.content if last_message else None,
                'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
                'unread_count': Communication.query.filter_by(
                    appointment_id=appointment.id,
                    is_read=False
                ).filter(Communication.sender_id != current_user.id).count()
            })
        
        return jsonify(appointments_data), 200
        
    except Exception as e:
        print(f"Error in get_patient_appointments: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    
@app.route('/api/appointment/<int:appointment_id>/payment-status')
@login_required
def get_appointment_payment_status(appointment_id):
    """Get payment status for a specific appointment"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if not verify_appointment_access(appointment, current_user):
        return jsonify({'error': 'Access denied'}), 403
    
    payment = Payment.query.filter_by(appointment_id=appointment_id).order_by(Payment.created_at.desc()).first()
    
    payment_status = 'pending'
    if payment:
        payment_status = payment.status
    elif appointment.status == 'completed':
        payment_status = 'completed'
    
    return jsonify({
        'appointment_id': appointment_id,
        'payment_status': payment_status,
        'payment_required': payment_status != 'paid' and current_user.role == 'patient'
    })

@app.route('/api/admins-list')
@login_required
def get_admins_list():
    """Get list of all admins for contact dropdown"""
    # Only allow patients and doctors to contact admins
    if current_user.role not in ['patient', 'doctor']:
        return jsonify({'error': 'Access denied'}), 403
    
    admins = User.query.filter_by(role='admin').all()
    
    admin_list = []
    for admin in admins:
        admin_data = {
            'id': admin.id,
            'first_name': admin.first_name,
            'last_name': admin.last_name,
            'email': admin.email,
            'profile_picture_url': get_user_profile_picture_url(admin) or '/static/images/default_avatar.png'
        }
        admin_list.append(admin_data)
    
    return jsonify({'admins': admin_list})

@app.route('/api/admin-conversation/<int:admin_id>')
@login_required
def get_admin_conversation(admin_id):
    """Get conversation messages between user and admin"""
    # Verify admin exists
    admin = User.query.get_or_404(admin_id)
    if admin.role != 'admin':
        return jsonify({'error': 'Not an admin'}), 400
    
    # Only allow patients and doctors
    if current_user.role not in ['patient', 'doctor']:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get messages from the conversation between current user and admin
    # Messages are stored with admin_id as recipient_id and current user as sender
    messages = Message.query.filter(
        db.or_(
            db.and_(
                Message.sender_id == current_user.id,
                Message.recipient_id == admin_id
            ),
            db.and_(
                Message.sender_id == admin_id,
                Message.recipient_id == current_user.id
            )
        )
    ).order_by(Message.created_at.asc()).all()
    
    message_list = []
    for msg in messages:
        message_data = {
            'id': msg.id,
            'sender_id': msg.sender_id,
            'recipient_id': msg.recipient_id,
            'content': msg.content,
            'created_at': msg.created_at.isoformat() if msg.created_at else None,
            'is_read': msg.is_read,
            'sender_name': f"{msg.sender.first_name} {msg.sender.last_name}",
            'sender_avatar': msg.sender.profile_picture_url or '/static/images/default_avatar.png'
        }
        message_list.append(message_data)
    
    return jsonify({'messages': message_list})


@app.route('/api/patient/appointments/categorized')
@login_required
def get_patient_appointments_categorized():
    """Get patient's appointments grouped by doctor with categorization: today, upcoming, completed, rescheduled, pending"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    # Get all appointments for this patient with doctor info
    appointments_data = db.session.query(
        Appointment,
        Doctor,
        User,
        Payment
    ).join(
        Doctor, Appointment.doctor_id == Doctor.id
    ).join(
        User, Doctor.user_id == User.id
    ).outerjoin(
        Payment, Appointment.id == Payment.appointment_id
    ).filter(
        Appointment.patient_id == patient.id
    ).order_by(Doctor.id, Appointment.appointment_date.desc()).all()
    
    # Group appointments by doctor and categorize
    doctors_appointments = {}  # {doctor_id: {'doctor_info': ..., 'today': [...], 'upcoming': [...], etc}}
    
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    for appointment, doctor, user, payment in appointments_data:
        doctor_id = doctor.id
        
        # Initialize doctor group if not exists
        if doctor_id not in doctors_appointments:
            doctors_appointments[doctor_id] = {
                'doctor': {
                    'id': doctor.id,
                    'user': {
                        'id': user.id,
                        'first_name': user.first_name,
                        'last_name': user.last_name
                    },
                    'specialization': doctor.specialization,
                    'consultation_fee': float(doctor.consultation_fee) if doctor.consultation_fee else 0.0
                },
                'today': [],
                'upcoming': [],
                'completed': [],
                'rescheduled': [],
                'pending': []
            }
        
        # Determine payment status
        payment_status = 'pending'
        if payment:
            payment_status = payment.status
        elif appointment.status == 'completed':
            payment_status = 'completed'
        
        # Ensure we're working with proper datetime objects
        appointment_date = appointment.appointment_date
        created_at = appointment.created_at
        
        appointment_data = {
            'id': appointment.id,
            'doctor_id': doctor_id,
            'appointment_date': appointment_date.isoformat() if appointment_date else None,
            'appointment_date_formatted': appointment_date.strftime('%d %b %Y') if appointment_date else None,
            'appointment_time': appointment_date.strftime('%H:%M') if appointment_date else None,
            'consultation_type': appointment.consultation_type,
            'symptoms': appointment.symptoms,
            'notes': appointment.notes,
            'status': appointment.status,
            'payment_status': payment_status,
            'rating': appointment.rating if hasattr(appointment, 'rating') else None,
            'created_at': created_at.isoformat() if created_at else None
        }
        
        # Categorize based on status and date
        if appointment.status == 'completed':
            doctors_appointments[doctor_id]['completed'].append(appointment_data)
        elif appointment.status == 'rescheduled':
            doctors_appointments[doctor_id]['rescheduled'].append(appointment_data)
        elif appointment.status == 'pending' or (appointment.status not in ['confirmed', 'scheduled', 'completed', 'rescheduled', 'cancelled']):
            doctors_appointments[doctor_id]['pending'].append(appointment_data)
        elif appointment.status in ['confirmed', 'scheduled']:
            if today_start <= appointment_date < today_end:
                doctors_appointments[doctor_id]['today'].append(appointment_data)
            elif appointment_date >= today_end:
                doctors_appointments[doctor_id]['upcoming'].append(appointment_data)
            else:
                # Past appointments that aren't marked completed
                doctors_appointments[doctor_id]['completed'].append(appointment_data)
        elif appointment.status == 'cancelled':
            # Skip cancelled appointments
            pass
    
    # Convert to list format
    appointments_by_doctor = list(doctors_appointments.values())
    
    return jsonify({
        'appointments_by_doctor': appointments_by_doctor,
        'total_doctors': len(doctors_appointments)
    })

# Add this route to handle profile picture errors gracefully
@app.route('/api/user/<int:user_id>/basic-info')
@login_required
def get_user_basic_info(user_id):
    """Get basic user info (name only)"""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate initials
    initials = 'U'
    if user.first_name and user.last_name:
        initials = f"{user.first_name[0]}{user.last_name[0]}".upper()
    elif user.first_name:
        initials = user.first_name[0].upper()
    elif user.last_name:
        initials = user.last_name[0].upper()
    elif user.username:
        initials = user.username[0].upper()
    
    return jsonify({
        'name': user.get_display_name(),
        'initials': initials
    })

# Add fallback for patient appointments
@app.route('/api/patient/appointments/fallback')
@login_required
def get_patient_appointments_fallback():
    """Fallback endpoint for patient appointments"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify([])
    
    # Simple fallback query
    appointments = Appointment.query.filter_by(patient_id=patient.id).all()
    
    appointments_data = []
    for appointment in appointments:
        doctor = db.session.get(Doctor, appointment.doctor_id)
        if doctor:
            doctor_user = db.session.get(User, doctor.user_id)
            appointments_data.append({
                'appointment_id': appointment.id,
                'doctor': {
                    'id': doctor.id,
                    'first_name': doctor_user.first_name if doctor_user else '',
                    'last_name': doctor_user.last_name if doctor_user else '',
                    'specialization': doctor.specialization,
                    'is_online': False
                },
                'appointment_date': appointment.appointment_date.isoformat() if appointment.appointment_date else None,
                'status': appointment.status,
                'paymentStatus': 'pending'
            })
    
    return jsonify(appointments_data)

# API to get all available doctors for booking
@app.route('/api/doctors', methods=['GET'])
@login_required
@csrf.exempt
def get_doctors():
    """Get all available doctors for appointment booking"""
    try:
        if current_user.role != 'patient':
            return jsonify({'error': 'Access denied'}), 403
        
        doctors = db.session.query(Doctor, User).join(
            User, Doctor.user_id == User.id
        ).filter(Doctor.availability == True).all()
        
        doctors_data = []
        for doctor, user in doctors:
            doctors_data.append({
                'id': doctor.id,
                'user_id': user.id,
                'first_name': getattr(user, 'first_name', ''),
                'last_name': getattr(user, 'last_name', ''),
                'phone': user.phone,
                'specialization': doctor.specialization,
                'license_number': doctor.license_number,
                'qualifications': doctor.qualifications,
                'experience_years': doctor.experience_years,
                'consultation_fee': doctor.consultation_fee,
                'availability': doctor.availability
            })
        
        return jsonify(doctors_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API to get appointments for a patient
@app.route('/api/doctor-patients', methods=['GET'])
@login_required
def get_api_doctor_patients():
    """Get all patients for doctor as JSON API"""
    if current_user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404
    
    # Get unique patients for this doctor
    patients_data = db.session.query(
        Patient,
        User
    ).join(
        User, Patient.user_id == User.id
    ).join(
        Appointment, Appointment.patient_id == Patient.id
    ).filter(
        Appointment.doctor_id == doctor.id
    ).distinct(Patient.id).all()
    
    patient_list = []
    for patient, user in patients_data:
        patient_list.append({
            'id': patient.id,
            'user_id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'phone': user.phone
        })
    
    return jsonify({'patients': patient_list, 'total': len(patient_list)})


@app.route('/doctor/patients', methods=['GET'])
def get_doctor_patients():
    """Render all patients for a doctor with their appointments categorized by status"""
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    doctor = current_user.doctor_profile
    if not doctor:
        flash('Doctor profile not found', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get all appointments for this doctor with patient info
        appointments_query = db.session.query(
            Appointment,
            Patient,
            User
        ).join(
            Patient, Appointment.patient_id == Patient.id
        ).join(
            User, Patient.user_id == User.id
        ).filter(
            Appointment.doctor_id == doctor.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Categorize appointments
        upcoming_appointments = []
        completed_appointments = []
        rescheduled_appointments = []
        pending_appointments = []
        
        now = datetime.now(timezone.utc)
        
        for appointment, patient, user in appointments_query:
            appointment_data = {
                'id': appointment.id,
                'patient': {
                    'id': patient.id,
                    'user': {
                        'id': user.id,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'email': user.email,
                        'phone': user.phone,
                        'profile_picture': user.profile_picture
                    },
                    'blood_type': patient.blood_type,
                    'allergies': patient.allergies
                },
                'appointment_date': appointment.appointment_date,
                'appointment_date_formatted': appointment.appointment_date.strftime('%B %d, %Y') if appointment.appointment_date else None,
                'appointment_time': appointment.appointment_date.strftime('%H:%M') if appointment.appointment_date else None,
                'consultation_type': appointment.consultation_type,
                'symptoms': appointment.symptoms,
                'notes': appointment.notes,
                'status': appointment.status,
                'urgency': appointment.urgency,
                'created_at': appointment.created_at
            }
            
            # Categorize based on status and date
            if appointment.status == 'completed':
                completed_appointments.append(appointment_data)
            elif appointment.status == 'rescheduled':
                rescheduled_appointments.append(appointment_data)
            elif appointment.status == 'pending':
                pending_appointments.append(appointment_data)
            elif appointment.status in ['confirmed', 'scheduled']:
                upcoming_appointments.append(appointment_data)
            else:
                # Default to pending for unknown statuses
                pending_appointments.append(appointment_data)
        
        return render_template('doctor/patients.html',
                             upcoming=upcoming_appointments,
                             completed=completed_appointments,
                             rescheduled=rescheduled_appointments,
                             pending=pending_appointments)
    
    except Exception as e:
        print(f"Error loading patients: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading patients', 'error')
        return render_template('doctor/patients.html',
                             upcoming=[],
                             completed=[],
                             rescheduled=[],
                             pending=[])

# API to get messages for appointment (patient/doctor communication)
@app.route('/api/appointment/<int:appointment_id>/messages', methods=['GET'])
@login_required
def get_appointment_messages_enhanced(appointment_id):
    """Get all messages for an appointment with enhanced data"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Verify access
        if current_user.role == 'patient':
            patient = Patient.query.filter_by(user_id=current_user.id).first()
            if not patient or appointment.patient_id != patient.id:
                return jsonify({'error': 'Access denied'}), 403
        elif current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            if not doctor or appointment.doctor_id != doctor.id:
                return jsonify({'error': 'Access denied'}), 403
        elif current_user.role != 'admin':
            return jsonify({'error': 'Access denied'}), 403
        
        messages = Communication.query.filter_by(
            appointment_id=appointment_id
        ).order_by(Communication.timestamp).all()
        
        messages_data = []
        for msg in messages:
            # Get file URL if exists
            file_url = None
            if msg.file_path:
                if msg.file_path.startswith('http'):
                    file_url = msg.file_path
                else:
                    file_url = url_for('download_communication_file', communication_id=msg.id, _external=True)
            
            # Get sender profile picture
            sender_profile_picture = None
            if msg.sender and msg.sender.profile_picture:
                if msg.sender.profile_picture.startswith('http'):
                    sender_profile_picture = msg.sender.profile_picture
                else:
                    sender_profile_picture = url_for('profile_picture', user_id=msg.sender.id, _external=True)
            
            messages_data.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'sender_name': safe_display_name(msg.sender),
                'sender_profile_picture': sender_profile_picture,
                'message_type': msg.message_type or 'text',
                'content': msg.content or '',
                'file_url': file_url,
                'file_name': os.path.basename(msg.file_path) if msg.file_path else None,
                'file_size': os.path.getsize(resolve_stored_path(msg.file_path)) if msg.file_path and os.path.exists(resolve_stored_path(msg.file_path)) else None,
                'timestamp': msg.timestamp.isoformat() if msg.timestamp else None,
                'is_sent': msg.sender_id == current_user.id,
                'is_read': msg.is_read if hasattr(msg, 'is_read') else True,
                'message_status': msg.message_status if hasattr(msg, 'message_status') else 'sent',
                'is_prescription': msg.message_type == 'prescription'
            })
        
        return jsonify({
            'appointment_id': appointment_id,
            'messages': messages_data,
            'count': len(messages_data)
        })
        
    except Exception as e:
        print(f"Error in get_appointment_messages: {str(e)}")
        return jsonify({
            'error': 'Failed to load messages',
            'message': str(e)
        }), 500
# API to send message in appointment
@app.route('/api/send-message', methods=['POST'])
@login_required
@csrf.exempt
def send_appointment_message():
    """Send a message in an appointment conversation"""
    data = request.get_json()
    appointment_id = data.get('appointment_id')
    content = data.get('content')
    
    if not appointment_id or not content:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if appointment.doctor_id != doctor.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    elif current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    communication = Communication(
        appointment_id=appointment_id,
        sender_id=current_user.id,
        message_type='text',
        content=content
    )
    
    db.session.add(communication)
    db.session.commit()
    
    return jsonify({'success': True, 'message_id': communication.id})

# API to send voice note
@app.route('/api/send-voice-note', methods=['POST'])
@login_required
@csrf.exempt
def send_voice_note():
    """Send a voice note in appointment"""
    appointment_id = request.form.get('appointment_id')
    
    if not appointment_id or 'audio' not in request.files:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if appointment.doctor_id != doctor.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    audio_file = request.files['audio']
    if audio_file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    # Generate filename
    filename = secure_filename(f"voice_{current_user.id}_{datetime.now(timezone.utc).timestamp()}.webm")
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Create uploads directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Save file
    audio_file.save(file_path)
    
    # Create communication record
    communication = Communication(
        appointment_id=appointment_id,
        sender_id=current_user.id,
        message_type='voice_note',
        content='[Voice Note]',
        file_path=file_path,
        file_name=filename,
        file_size=os.path.getsize(file_path),
        message_status='delivered'
    )
    
    db.session.add(communication)
    db.session.flush()  # Get the ID before commit
    
    # Prepare file URL
    file_url = f'/static/uploads/{filename}'
    
    # Get recipient based on current user role
    if current_user.role == 'patient':
        recipient_id = appointment.doctor.user_id
    else:
        recipient_id = appointment.patient.user_id
    
    # Mark as delivered if recipient is online
    recipient_socket_id = user_sockets.get(recipient_id)
    if recipient_socket_id:
        communication.message_status = 'delivered'
    
    db.session.commit()
    
    # Broadcast to appointment room via Socket.IO
    appointment_room = f'appointment_{appointment_id}'
    message_data = {
        'id': communication.id,
        'sender_id': current_user.id,
        'sender_name': safe_display_name(current_user),
        'content': '[Voice Note]',
        'message_type': 'voice_note',
        'timestamp': communication.created_at.isoformat(),
        'message_status': communication.message_status,
        'file_url': file_url,
        'file_name': filename,
        'file_size': communication.file_size,
        'appointment_id': appointment_id
    }
    
    # Emit to all in the room
    socketio.emit('message_received', message_data, room=appointment_room)
    
    return jsonify({
        'success': True,
        'message_id': communication.id,
        'file_url': file_url,
        'message_status': communication.message_status
    })

# API for doctor communication

@app.route('/api/doctor/patient/<int:patient_id>/latest-appointment')
@login_required
def get_patient_latest_appointment(patient_id):
    """Get the latest appointment for a specific patient with the current doctor"""
    if current_user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404
    
    # Get latest appointment between this doctor and patient
    appointment = Appointment.query.filter_by(
        doctor_id=doctor.id,
        patient_id=patient_id
    ).order_by(Appointment.appointment_date.desc()).first()
    
    if appointment:
        return jsonify({
            'appointment_id': appointment.id,
            'appointment_date': appointment.appointment_date.isoformat(),
            'status': appointment.status
        })
    else:
        return jsonify({'appointment_id': None})

# Add endpoint for patient to get doctor's latest appointment
@app.route('/api/patient/doctor/<int:doctor_id>/latest-appointment')
@login_required
def get_doctor_latest_appointment(doctor_id):
    """Get the latest appointment for a specific doctor with the current patient"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    # Get latest appointment between this patient and doctor
    appointment = Appointment.query.filter_by(
        doctor_id=doctor_id,
        patient_id=patient.id
    ).order_by(Appointment.appointment_date.desc()).first()
    
    if appointment:
        return jsonify({
            'appointment_id': appointment.id,
            'appointment_date': appointment.appointment_date.isoformat(),
            'status': appointment.status
        })
    else:
        return jsonify({'appointment_id': None})

# Add endpoint to start new consultation
@app.route('/api/doctor/start-consultation', methods=['POST'])
@login_required
@csrf.exempt
def start_consultation():
    """Start a new consultation with a patient"""
    if current_user.role != 'doctor':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    data = request.get_json()
    patient_id = data.get('patient_id')
    
    if not patient_id:
        return jsonify({'success': False, 'error': 'Patient ID required'}), 400
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'success': False, 'error': 'Doctor profile not found'}), 404
    
    patient = db.session.get(Patient, patient_id)
    if not patient:
        return jsonify({'success': False, 'error': 'Patient not found'}), 404
    
    # Create a new appointment
    appointment = Appointment(
        patient_id=patient_id,
        doctor_id=doctor.id,
        appointment_date=datetime.now(timezone.utc),
        consultation_type='message',
        status='confirmed'
    )
    
    db.session.add(appointment)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'appointment_id': appointment.id,
        'message': 'Consultation started successfully'
    })


@app.route('/api/doctor/patient/<int:patient_id>/messages', methods=['GET'])
@login_required
def get_doctor_patient_messages(patient_id):
    """Get messages between doctor and patient"""
    if current_user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    patient = Patient.query.get_or_404(patient_id)
    
    # Get the latest appointment between doctor and patient
    appointment = Appointment.query.filter_by(
        doctor_id=doctor.id,
        patient_id=patient_id
    ).order_by(Appointment.appointment_date.desc()).first()
    
    if not appointment:
        return jsonify({'error': 'No appointment found'}), 404
    
    messages = Communication.query.filter_by(
        appointment_id=appointment.id
    ).order_by(Communication.timestamp).all()
    
    messages_data = []
    for msg in messages:
        messages_data.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'content': msg.content,
            'timestamp': msg.timestamp.isoformat(),
            'is_sent': msg.sender_id == current_user.id,
            'is_read': msg.is_read
        })
    
    return jsonify(messages_data)

@app.route('/api/doctor/send-message', methods=['POST'])
@login_required
@csrf.exempt
def send_doctor_message():
    """Send message from doctor to patient"""
    if current_user.role != 'doctor':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    data = request.get_json()
    patient_id = data.get('patient_id')
    content = data.get('content')
    
    if not patient_id or not content:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    
    # Get latest appointment
    appointment = Appointment.query.filter_by(
        doctor_id=doctor.id,
        patient_id=patient_id
    ).order_by(Appointment.appointment_date.desc()).first()
    
    if not appointment:
        return jsonify({'success': False, 'error': 'No appointment found'}), 404
    
    communication = Communication(
        appointment_id=appointment.id,
        sender_id=current_user.id,
        message_type='text',
        content=content
    )
    
    db.session.add(communication)
    db.session.commit()
    
    return jsonify({'success': True, 'message_id': communication.id})

# API for patient communication
@app.route('/api/patient/doctors')
@login_required
def get_patient_doctors():
    """Get doctors for patient communication page"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    try:
        # Get appointments with doctor info
        appointments = db.session.query(
            Appointment,
            Doctor,
            User
        ).join(
            Doctor, Appointment.doctor_id == Doctor.id
        ).join(
            User, Doctor.user_id == User.id
        ).filter(
            Appointment.patient_id == patient.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Group by doctor and get latest info
        doctors_map = {}
        for appointment, doctor, user in appointments:
            if doctor.id not in doctors_map:
                # Get last message
                last_message = Communication.query.filter_by(
                    appointment_id=appointment.id
                ).order_by(Communication.timestamp.desc()).first()
                
                # Check if doctor is online
                is_online = user.id in user_sockets
                
                # Get payment status
                payment = Payment.query.filter_by(
                    appointment_id=appointment.id
                ).order_by(Payment.created_at.desc()).first()
                
                doctors_map[doctor.id] = {
                    'doctor': {
                        'id': doctor.id,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'specialization': doctor.specialization,
                        'is_online': is_online,
                        'profile_picture_url': url_for('profile_picture', user_id=user.id, _external=True) if user else None
                    },
                    'last_appointment': {
                        'id': appointment.id,
                        'date': appointment.appointment_date.isoformat() if appointment.appointment_date else None,
                        'status': appointment.status
                    },
                    'last_message': last_message.content if last_message else None,
                    'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
                    'unread_count': Communication.query.join(
                        Appointment, Communication.appointment_id == Appointment.id
                    ).filter(
                        Appointment.patient_id == patient.id,
                        Appointment.doctor_id == doctor.id,
                        Communication.is_read == False,
                        Communication.sender_id != current_user.id
                    ).count(),
                    'payment_status': payment.status if payment else 'pending'
                }
        
        return jsonify(list(doctors_map.values()))
        
    except Exception as e:
        print(f"Error in get_patient_doctors: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/user/<int:user_id>/basic')
@login_required
def get_user_basic(user_id):
    """Get basic user info for avatar"""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'name': 'User', 'initials': 'U'})
    
    # Generate initials
    initials = 'U'
    if user.first_name and user.last_name:
        initials = f"{user.first_name[0]}{user.last_name[0]}".upper()
    elif user.first_name:
        initials = user.first_name[0].upper()
    elif user.last_name:
        initials = user.last_name[0].upper()
    elif user.username:
        initials = user.username[0].upper()
    
    return jsonify({
        'name': user.get_display_name(),
        'initials': initials
    })

@app.route('/api/patient/doctor/<int:doctor_id>/messages', methods=['GET'])
@login_required
def get_patient_doctor_messages(doctor_id):
    """Get messages between patient and doctor"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    doctor = Doctor.query.get_or_404(doctor_id)
    
    # Get the latest appointment between patient and doctor
    appointment = Appointment.query.filter_by(
        doctor_id=doctor_id,
        patient_id=patient.id
    ).order_by(Appointment.appointment_date.desc()).first()
    
    if not appointment:
        return jsonify({'error': 'No appointment found'}), 404
    
    messages = Communication.query.filter_by(
        appointment_id=appointment.id
    ).order_by(Communication.timestamp).all()
    
    messages_data = []
    for msg in messages:
        messages_data.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'content': msg.content,
            'timestamp': msg.timestamp.isoformat(),
            'is_sent': msg.sender_id == current_user.id,
            'is_read': msg.is_read,
            'is_prescription': msg.message_type == 'prescription'
        })
    
    return jsonify(messages_data)

@app.route('/api/patient/send-message', methods=['POST'])
@login_required
@csrf.exempt
def send_patient_message():
    """Send message from patient to doctor"""
    if current_user.role != 'patient':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    data = request.get_json()
    doctor_id = data.get('doctor_id')
    content = data.get('content')
    
    if not doctor_id or not content:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    
    # Get latest appointment
    appointment = Appointment.query.filter_by(
        doctor_id=doctor_id,
        patient_id=patient.id
    ).order_by(Appointment.appointment_date.desc()).first()
    
    if not appointment:
        return jsonify({'success': False, 'error': 'No appointment found'}), 404
    
    communication = Communication(
        appointment_id=appointment.id,
        sender_id=current_user.id,
        message_type='text',
        content=content
    )
    
    db.session.add(communication)
    db.session.commit()
    
    return jsonify({'success': True, 'message_id': communication.id})

# ============================================
# VIDEO/VOICE CALL ROUTES
# ============================================

@app.route('/incoming-video-call/<int:appointment_id>')
@login_required
def incoming_video_call(appointment_id):
    """Incoming video call notification page"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify user is the recipient of this call (not the initiator)
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or appointment.patient_id != patient.id:
            return redirect(url_for('index'))
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor or appointment.doctor_id != doctor.id:
            return redirect(url_for('index'))
    
    return render_template('communication/incoming_video_call.html', appointment=appointment)

@app.route('/incoming-voice-call/<int:appointment_id>')
@login_required
def incoming_voice_call(appointment_id):
    """Incoming voice call notification page"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify user is the recipient of this call (not the initiator)
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or appointment.patient_id != patient.id:
            return redirect(url_for('index'))
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor or appointment.doctor_id != doctor.id:
            return redirect(url_for('index'))
    
    return render_template('communication/incoming_voice_call.html', appointment=appointment)

@app.route('/video-call/<int:appointment_id>')
@login_required
def video_call(appointment_id):
    """Video call page for appointments"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify user has access to this appointment
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or appointment.patient_id != patient.id:
            return redirect(url_for('index'))
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor or appointment.doctor_id != doctor.id:
            return redirect(url_for('index'))
    
    return render_template('communication/video_call.html', appointment=appointment)

@app.route('/video-call/doctor/<int:doctor_id>')
@login_required
def video_call_doctor(doctor_id):
    """Video call with doctor"""
    if current_user.role != 'patient':
        return redirect(url_for('index'))
    
    doctor = Doctor.query.get_or_404(doctor_id)
    patient = Patient.query.filter_by(user_id=current_user.id).first_or_404()
    
    # Get or create an appointment for this video call
    appointment = Appointment.query.filter_by(
        patient_id=patient.id,
        doctor_id=doctor.id
    ).first()
    
    if not appointment:
        # Create a new appointment for this video call
        appointment = Appointment(
            patient_id=patient.id,
            doctor_id=doctor.id,
            status='ongoing'
        )
        db.session.add(appointment)
        db.session.commit()
    
    return render_template('communication/video_call.html', appointment=appointment)

@app.route('/video-call/patient/<int:patient_id>')
@login_required
def video_call_patient(patient_id):
    """Video call with patient"""
    if current_user.role != 'doctor':
        return redirect(url_for('index'))
    
    patient = Patient.query.get_or_404(patient_id)
    doctor = Doctor.query.filter_by(user_id=current_user.id).first_or_404()
    
    # Get or create an appointment for this video call
    appointment = Appointment.query.filter_by(
        patient_id=patient.id,
        doctor_id=doctor.id
    ).first()
    
    if not appointment:
        # Create a new appointment for this video call
        appointment = Appointment(
            patient_id=patient.id,
            doctor_id=doctor.id,
            status='ongoing'
        )
        db.session.add(appointment)
        db.session.commit()
    
    return render_template('communication/video_call.html', appointment=appointment)

@app.route('/voice-call/<int:appointment_id>')
@login_required
def voice_call(appointment_id):
    """Voice call page for appointments"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify user has access to this appointment
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or appointment.patient_id != patient.id:
            return redirect(url_for('index'))
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor or appointment.doctor_id != doctor.id:
            return redirect(url_for('index'))
    
    return render_template('communication/voice_call.html', appointment=appointment)

@app.route('/outgoing-call/<int:appointment_id>')
@login_required
def outgoing_call(appointment_id):
    """Outgoing call UI for caller: opens a small window showing callee info and call status."""
    appointment = db.session.get(Appointment, appointment_id)
    return render_template('communication/outgoing_call.html', appointment=appointment)

@app.route('/voice-call/doctor/<int:doctor_id>')
@login_required
def voice_call_doctor(doctor_id):
    """Voice call with doctor"""
    if current_user.role != 'patient':
        return redirect(url_for('index'))
    
    doctor = Doctor.query.get_or_404(doctor_id)
    patient = Patient.query.filter_by(user_id=current_user.id).first_or_404()
    
    # Get or create an appointment for this voice call
    appointment = Appointment.query.filter_by(
        patient_id=patient.id,
        doctor_id=doctor.id
    ).first()
    
    if not appointment:
        # Create a new appointment for this voice call
        appointment = Appointment(
            patient_id=patient.id,
            doctor_id=doctor.id,
            status='ongoing'
        )
        db.session.add(appointment)
        db.session.commit()
    
    return render_template('communication/voice_call.html', appointment=appointment)

@app.route('/voice-call/patient/<int:patient_id>')
@login_required
def voice_call_patient(patient_id):
    """Voice call with patient"""
    if current_user.role != 'doctor':
        return redirect(url_for('index'))
    
    patient = Patient.query.get_or_404(patient_id)
    doctor = Doctor.query.filter_by(user_id=current_user.id).first_or_404()
    
    # Get or create an appointment for this voice call
    appointment = Appointment.query.filter_by(
        patient_id=patient.id,
        doctor_id=doctor.id
    ).first()
    
    if not appointment:
        # Create a new appointment for this voice call
        appointment = Appointment(
            patient_id=patient.id,
            doctor_id=doctor.id,
            status='ongoing'
        )
        db.session.add(appointment)
        db.session.commit()
    
    return render_template('communication/voice_call.html', appointment=appointment)

@app.route('/doctor/<int:doctor_id>')
@login_required
def doctor_profile(doctor_id):
    """Doctor profile page"""
    doctor = Doctor.query.get_or_404(doctor_id)
    user = User.query.get_or_404(doctor.user_id)
    
    return render_template('doctor/profile.html', doctor=doctor, user=user)


@app.route('/doctors')
def doctors():
    """Public list of available doctors"""
    doctors = db.session.query(Doctor, User).join(
        User, Doctor.user_id == User.id
    ).filter(Doctor.availability == True).all()

    return render_template('doctors.html', doctors=doctors)
@app.route('/api/prescription/form')
@login_required
def get_prescription_form():
    """Get prescription form HTML"""
    if current_user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    patient_id = request.args.get('patient_id')
    appointment_id = request.args.get('appointment_id')
    
    return '''
    <form id="prescriptionFormData">
        <input type="hidden" name="patient_id" value="''' + (patient_id or '') + '''">
        <input type="hidden" name="appointment_id" value="''' + (appointment_id or '') + '''">
        
        <div class="mb-3">
            <label class="form-label">Medication Name</label>
            <input type="text" class="form-control" name="medication" required>
        </div>
        
        <div class="mb-3">
            <label class="form-label">Dosage</label>
            <input type="text" class="form-control" name="dosage" placeholder="e.g., 500mg twice daily" required>
        </div>
        
        <div class="mb-3">
            <label class="form-label">Duration</label>
            <input type="text" class="form-control" name="duration" placeholder="e.g., 7 days" required>
        </div>
        
        <div class="mb-3">
            <label class="form-label">Instructions</label>
            <textarea class="form-control" name="instructions" rows="3" placeholder="Additional instructions..."></textarea>
        </div>
        
        <div class="mb-3">
            <label class="form-label">Refills</label>
            <input type="number" class="form-control" name="refills" min="0" max="5" value="0">
        </div>
        
        <div class="text-end">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-primary" id="savePrescriptionBtn">Save Prescription</button>
        </div>
    </form>
    '''

# Add endpoint to save prescription
@app.route('/api/prescription/save', methods=['POST'])
@login_required
@csrf.exempt
def save_prescription():
    """Save a new prescription"""
    if current_user.role != 'doctor':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    patient_id = request.form.get('patient_id')
    appointment_id = request.form.get('appointment_id')
    medication = request.form.get('medication')
    dosage = request.form.get('dosage')
    instructions = request.form.get('instructions')
    
    if not all([patient_id, appointment_id, medication, dosage]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'success': False, 'error': 'Doctor profile not found'}), 404
    
    # Create prescription
    prescription = Prescription(
        doctor_id=doctor.id,
        patient_id=patient_id,
        appointment_id=appointment_id,
        medication=medication,
        dosage=dosage,
        instructions=instructions
    )
    
    db.session.add(prescription)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'prescription_id': prescription.id,
        'message': 'Prescription saved successfully'
    })


@app.route('/prescription/<int:prescription_id>')
@login_required
def view_prescription(prescription_id):
    """Render a prescription for viewing (patient/doctor/admin)."""
    prescription = Prescription.query.get_or_404(prescription_id)

    # Access control: allow patient owner, prescribing doctor, or admin
    if current_user.role == 'patient' and prescription.patient.user_id != current_user.id:
        return redirect(url_for('index'))
    if current_user.role == 'doctor' and prescription.doctor.user_id != current_user.id:
        # allow doctor to view only their own prescriptions
        return redirect(url_for('index'))

    # Determine expiry
    now = datetime.now(timezone.utc)
    prescription_expired = bool(prescription.is_expired or (prescription.expiry_date and prescription.expiry_date < now))

    # Log audit: viewed
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=(current_user.id if current_user.is_authenticated else None), action='viewed')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return render_template('patient/prescription.html', prescription=prescription, prescription_expired=prescription_expired)


@app.route('/prescription/<int:prescription_id>/print')
@login_required
def print_prescription(prescription_id):
    prescription = Prescription.query.get_or_404(prescription_id)

    # Access control similar to view_prescription
    if current_user.role == 'patient' and prescription.patient.user_id != current_user.id:
        return redirect(url_for('index'))
    if current_user.role == 'doctor' and prescription.doctor.user_id != current_user.id:
        return redirect(url_for('index'))

    now = datetime.now(timezone.utc)
    prescription_expired = bool(prescription.is_expired or (prescription.expiry_date and prescription.expiry_date < now))

    # Render same template but include print-on-load in the template
    # Audit print action
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=(current_user.id if current_user.is_authenticated else None), action='printed')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return render_template('patient/prescription.html', prescription=prescription, prescription_expired=prescription_expired, print_mode=True)


@app.route('/prescription/<int:prescription_id>/download')
@login_required
def download_prescription_pdf(prescription_id):
    """Generate a PDF for the prescription and send it to the user."""
    prescription = Prescription.query.get_or_404(prescription_id)

    # Access control
    if current_user.role == 'patient' and prescription.patient.user_id != current_user.id:
        return redirect(url_for('index'))
    if current_user.role == 'doctor' and prescription.doctor.user_id != current_user.id:
        return redirect(url_for('index'))

    # Richer PDF: include logo, clinic header, doctor's signature (if available) and QR code
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
    import io, qrcode

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Clinic logo
    try:
        logo_path = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), 'logo.png')
        if os.path.exists(logo_path):
            logo = ImageReader(logo_path)
            c.drawImage(logo, 50, height - 90, width=120, preserveAspectRatio=True, mask='auto')
    except Exception:
        pass

    # Clinic header
    c.setFont('Helvetica-Bold', 18)
    c.drawString(200, height - 60, 'Makokha Medical Centre')
    c.setFont('Helvetica', 11)
    c.drawString(200, height - 76, 'Telemedicine & Clinical Services')

    y = height - 110
    c.setFont('Helvetica', 11)
    c.drawString(50, y, f'Date: {prescription.created_at.strftime("%Y-%m-%d %H:%M UTC")}')
    y -= 18
    doctor_name = getattr(prescription.doctor.user, 'first_name', '') or ''
    doctor_last = getattr(prescription.doctor.user, 'last_name', '') or ''
    c.drawString(50, y, f'Prescribed by: Dr. {doctor_name} {doctor_last}')
    y -= 26

    # Medication details
    c.setFont('Helvetica-Bold', 12)
    c.drawString(50, y, 'Medication:')
    c.setFont('Helvetica', 12)
    c.drawString(150, y, prescription.medication)
    y -= 20
    c.setFont('Helvetica-Bold', 12)
    c.drawString(50, y, 'Dosage:')
    c.setFont('Helvetica', 12)
    c.drawString(150, y, prescription.dosage)
    y -= 24

    c.setFont('Helvetica-Bold', 12)
    c.drawString(50, y, 'Instructions:')
    y -= 16
    text = c.beginText(50, y)
    text.setFont('Helvetica', 11)
    for line in (prescription.instructions or '').split('\n'):
        text.textLine(line)
    c.drawText(text)

    # QR code linking to the prescription verify/view URL
    try:
        verify_url = request.host_url.rstrip('/') + url_for('view_prescription', prescription_id=prescription.id)
        qr = qrcode.make(verify_url)
        qr_buf = io.BytesIO()
        qr.save(qr_buf, format='PNG')
        qr_buf.seek(0)
        qr_img = ImageReader(qr_buf)
        c.drawImage(qr_img, width - 150, 80, width=90, preserveAspectRatio=True, mask='auto')
    except Exception:
        pass

    # Signature image if available under uploads/signatures/doctor_{id}.png
    try:
        sig_path = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), 'signatures', f'doctor_{prescription.doctor.id}.png')
        if os.path.exists(sig_path):
            sig = ImageReader(sig_path)
            c.drawImage(sig, 50, 80, width=180, preserveAspectRatio=True, mask='auto')
        else:
            c.setFont('Helvetica-Oblique', 12)
            c.drawString(50, 110, f'Signed: Dr. {doctor_name} {doctor_last}')
    except Exception:
        c.setFont('Helvetica-Oblique', 12)
        c.drawString(50, 110, f'Signed: Dr. {doctor_name} {doctor_last}')

    # If expired, add red rubber-stamp
    now = datetime.now(timezone.utc)
    expired = bool(prescription.is_expired or (prescription.expiry_date and prescription.expiry_date < now))
    if expired:
        c.setFillColorRGB(1, 0, 0)
        c.setFont('Helvetica-Bold', 48)
        c.saveState()
        c.translate(300, 300)
        c.rotate(30)
        c.drawCentredString(0, 0, 'EXPIRED')
        c.restoreState()

    c.showPage()
    c.save()
    buffer.seek(0)

    # Audit download
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=(current_user.id if current_user.is_authenticated else None), action='downloaded')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return send_file(buffer, as_attachment=True, download_name=f'prescription_{prescription.id}.pdf', mimetype='application/pdf')


@app.route('/prescription/<int:prescription_id>/expire', methods=['POST'])
@login_required
def expire_prescription(prescription_id):
    """Mark a prescription as expired (e.g., by dispensing person)."""
    prescription = Prescription.query.get_or_404(prescription_id)
    # Access control -- allow admin or doctor or designated staff
    if current_user.role not in ('admin', 'doctor'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    prescription.is_expired = True
    prescription.expired_by = current_user.id
    prescription.dispensed_at = datetime.now(timezone.utc)
    db.session.commit()
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=current_user.id, action='expired')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'success': True})


@app.route('/prescription/<int:prescription_id>/dispense', methods=['POST'])
@login_required
def dispense_prescription(prescription_id):
    """Mark prescription as dispensed/signed by dispensing person."""
    prescription = Prescription.query.get_or_404(prescription_id)
    if current_user.role not in ('admin', 'doctor'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    prescription.dispensed_by = current_user.id
    prescription.dispensed_at = datetime.now(timezone.utc)
    db.session.commit()
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=current_user.id, action='dispensed')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'success': True})


@app.route('/doctor/prescribed')
@login_required
def doctor_prescribed_list():
    if current_user.role != 'doctor':
        return redirect(url_for('index'))

    doctor = Doctor.query.filter_by(user_id=current_user.id).first_or_404()
    prescriptions = Prescription.query.filter_by(doctor_id=doctor.id).order_by(Prescription.created_at.desc()).all()
    return render_template('doctor/prescribed.html', prescriptions=prescriptions)
# ============================================
# SOCKET.IO EVENT HANDLERS - REAL-TIME COMMUNICATION
# ============================================

@socketio.on_error_default
def default_error_handler(e):
    """Handle Socket.IO errors"""
    print(f'Socket.IO error: {e}')
    import traceback
    traceback.print_exc()

# Add this route BEFORE your main Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    """Handle Socket.IO connection"""
    if current_user.is_authenticated:
        # Ensure we keep a list of socket ids per user (support multiple tabs/devices)
        existing = user_sockets.get(current_user.id)
        sid = request.sid
        if isinstance(existing, list):
            if sid not in existing:
                existing.append(sid)
            user_sockets[current_user.id] = existing
        elif existing:
            # existing is present but not a list (legacy value), coerce to list
            try:
                user_sockets[current_user.id] = [existing, sid] if existing != sid else [sid]
            except Exception:
                user_sockets[current_user.id] = [sid]
        else:
            user_sockets[current_user.id] = [sid]
        user_last_seen[current_user.id] = datetime.now(timezone.utc).isoformat()
        
        emit('connection_response', {'data': 'Connected to server'})
        print(f'User {current_user.id} connected: {request.sid}')
        try:
            print(f'Current user_sockets mapping ({len(user_sockets)}): {user_sockets}')
        except Exception:
            pass
        return True
    return False


# Make ICE servers available to templates via context processor
@app.context_processor
def inject_ice_servers():
    try:
        ice = app.config.get('ICE_SERVERS', [{'urls': 'stun:stun.l.google.com:19302'}])
        return {'ice_servers': ice}
    except Exception:
        return {'ice_servers': [{'urls': 'stun:stun.l.google.com:19302'}]}

# Also add this route for health check
@app.route('/socket.io/')
def socketio_health():
    """Handle Socket.IO health check"""
    return jsonify({'status': 'ok', 'socketio': 'enabled'})
    
@socketio.on('message_delivered')
def handle_message_delivered(data):
    """Mark a message as delivered"""
    if not current_user.is_authenticated:
        return
    
    message_id = data.get('message_id')
    appointment_id = data.get('appointment_id')
    
    if not message_id or not appointment_id:
        return
    
    # Verify the user is part of this appointment
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        return
    
    # Check access
    if not verify_appointment_access(appointment, current_user):
        return
    
    # Update message status
    message = db.session.get(Communication, message_id)
    if message and message.appointment_id == appointment_id:
        message.message_status = 'delivered'
        db.session.commit()
        
        # Notify sender that message was delivered
        emit('message_status_updated', {
            'message_id': message_id,
            'status': 'delivered',
            'appointment_id': appointment_id
        }, room=f'appointment_{appointment_id}')
        
        # If the recipient is online, mark as read immediately
        recipient_id = message.sender_id if message.sender_id != current_user.id else None
        if recipient_id and recipient_id in user_sockets:
            message.message_status = 'read'
            message.is_read = True
            db.session.commit()
            
            emit('message_status_updated', {
                'message_id': message_id,
                'status': 'read',
                'appointment_id': appointment_id
            }, room=f'appointment_{appointment_id}')

@socketio.on('disconnect')
def handle_disconnect(reason=None):
    """Handle user disconnection with cleanup."""
    sid = request.sid
    try:
        # Remove this sid from any user's socket list
        for uid, sids in list(user_sockets.items()):
            try:
                # ensure we treat sids as list
                if isinstance(sids, list):
                    if sid in sids:
                        sids.remove(sid)
                        if not sids:
                            user_sockets.pop(uid, None)
                            user_last_seen[uid] = datetime.now(timezone.utc).isoformat()
                        else:
                            user_sockets[uid] = sids
                else:
                    # legacy single-sid string
                    if sids == sid:
                        user_sockets.pop(uid, None)
                        user_last_seen[uid] = datetime.now(timezone.utc).isoformat()
            except Exception:
                user_sockets.pop(uid, None)

        # If current_user is authenticated, update last seen and cleanup active_calls
        if current_user.is_authenticated:
            user_id = current_user.id
            user_last_seen[user_id] = datetime.now(timezone.utc).isoformat()
            # Clean up active_calls entries referencing this user
            for apt_id, users in list(active_calls.items()):
                try:
                    if isinstance(users, dict) and user_id in users:
                        del users[user_id]
                        if not users:
                            del active_calls[apt_id]
                except Exception:
                    pass

        try:
            print(f'User disconnected (sid={sid}). Current user_sockets mapping ({len(user_sockets)}): {user_sockets}')
        except Exception:
            pass

    except Exception as e:
        print(f'Error in handle_disconnect: {e}')

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    try:
        # Simple check without database query to avoid threading issues
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'service': 'telemedicine-platform'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@socketio.on('user_online_status')
def handle_user_online_status(data):
    """Handle user online/offline status updates"""
    if not current_user.is_authenticated:
        return
    
    user_id = current_user.id
    is_online = data.get('is_online', True)
    
    if is_online:
        # Ensure list semantics for user_sockets (support multiple tabs/devices)
        sid = request.sid
        existing = user_sockets.get(user_id)
        if isinstance(existing, list):
            if sid not in existing:
                existing.append(sid)
            user_sockets[user_id] = existing
        elif existing:
            try:
                user_sockets[user_id] = [existing, sid] if existing != sid else [sid]
            except Exception:
                user_sockets[user_id] = [sid]
        else:
            user_sockets[user_id] = [sid]
        user_last_seen[user_id] = datetime.now(timezone.utc).isoformat()
        
        # Notify relevant users based on role
        if current_user.role == 'doctor':
            # Notify all patients who have appointments with this doctor
            doctor = Doctor.query.filter_by(user_id=user_id).first()
            if doctor:
                appointments = Appointment.query.filter_by(doctor_id=doctor.id).all()
                patient_ids = set([app.patient_id for app in appointments])
                
                for patient_id in patient_ids:
                    patient = db.session.get(Patient, patient_id)
                    if patient:
                        # Emit to the patient's personal room
                        socketio.emit('doctor_online', {
                            'doctor_id': doctor.id,
                            'doctor_name': current_user.get_display_name()
                        }, room=f'user_{patient.user_id}')
        
        elif current_user.role == 'patient':
            # Notify all doctors who have appointments with this patient
            patient = Patient.query.filter_by(user_id=user_id).first()
            if patient:
                appointments = Appointment.query.filter_by(patient_id=patient.id).all()
                doctor_ids = set([app.doctor_id for app in appointments])
                
                for doctor_id in doctor_ids:
                    doctor = db.session.get(Doctor, doctor_id)
                    if doctor:
                        socketio.emit('patient_online', {
                            'patient_id': patient.id,
                            'patient_name': current_user.get_display_name()
                        }, room=f'user_{doctor.user_id}')
    
    else:
        if user_id in user_sockets:
            user_sockets.pop(user_id, None)
        
        # Notify relevant users about offline status
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=user_id).first()
            if doctor:
                appointments = Appointment.query.filter_by(doctor_id=doctor.id).all()
                patient_ids = set([app.patient_id for app in appointments])
                
                for patient_id in patient_ids:
                    patient = db.session.get(Patient, patient_id)
                    if patient:
                        socketio.emit('doctor_offline', {
                            'doctor_id': doctor.id
                        }, room=f'user_{patient.user_id}')
        
        elif current_user.role == 'patient':
            patient = Patient.query.filter_by(user_id=user_id).first()
            if patient:
                appointments = Appointment.query.filter_by(patient_id=patient.id).all()
                doctor_ids = set([app.doctor_id for app in appointments])
                
                for doctor_id in doctor_ids:
                    doctor = db.session.get(Doctor, doctor_id)
                    if doctor:
                        socketio.emit('patient_offline', {
                            'patient_id': patient.id
                        }, room=f'user_{doctor.user_id}')

# ============================================
# MESSAGING EVENTS
# ============================================

@socketio.on('send_message')
def handle_send_message_enhanced(data):
    """Handle real-time message sending with WhatsApp-style features"""
    if not current_user.is_authenticated:
        emit('message_error', {'error': 'Not authenticated'})
        return False

    try:
        # Simple rate limiting: max 30 messages per minute per user
        now_ts = time.time()
        user_bucket = message_rate.get(current_user.id, [])
        # keep only last 60s
        user_bucket = [t for t in user_bucket if now_ts - t < 60]
        if len(user_bucket) >= 30:
            emit('message_error', {'error': 'Rate limit exceeded'});
            return {'success': False, 'error': 'rate_limited'}
        user_bucket.append(now_ts)
        message_rate[current_user.id] = user_bucket
        appointment_id = data.get('appointment_id')
        content = data.get('content')
        message_type = data.get('message_type', 'text')
        file_url = data.get('file_url')
        file_size = data.get('file_size')

        if not appointment_id or (not content and message_type == 'text'):
            emit('message_error', {'error': 'Invalid data'})
            return False

        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            emit('message_error', {'error': 'Appointment not found'})
            return False

        # Verify access
        if not verify_appointment_access(appointment, current_user):
            emit('message_error', {'error': 'Access denied'})
            return False

        # Save message to database with proper timestamp
        communication = Communication(
            appointment_id=appointment_id,
            sender_id=current_user.id,
            message_type=message_type,
            content=content,
            message_status='sent',
            is_read=False,
            timestamp=datetime.now(timezone.utc)
        )
        
        if file_url:
            communication.file_path = file_url
        
        db.session.add(communication)
        db.session.flush()  # Get the ID without committing
        message_id = communication.id
        db.session.commit()

        # Prepare complete message data for broadcast
        message_data = {
            'id': message_id,
            'appointment_id': appointment_id,
            'sender_id': current_user.id,
            'sender_name': safe_display_name(current_user),
            'message_type': message_type,
            'content': content,
            'timestamp': communication.timestamp.isoformat(),
            'message_status': 'sent',
            'file_url': file_url,
            'file_size': file_size
        }

        # Broadcast to appointment room
        appointment_room = f'appointment_{appointment_id}'
        emit('message_received', message_data, room=appointment_room, skip_sid=None)
        
        # Check if recipient is online for immediate delivery status
        recipient_id = None
        if current_user.role == 'patient':
            doctor = db.session.get(Doctor, appointment.doctor_id)
            recipient_id = doctor.user_id if doctor else None
        else:
            patient = db.session.get(Patient, appointment.patient_id)
            recipient_id = patient.user_id if patient else None
        
        # Mark as delivered immediately if recipient is in the appointment room
        # This gives instant double-tick feedback like WhatsApp
        if recipient_id and recipient_id in user_sockets:
            communication.message_status = 'delivered'
            db.session.commit()
            # Broadcast delivery status immediately to all clients in room
            emit('message_status_updated', {
                'message_id': message_id,
                'status': 'delivered',
                'appointment_id': appointment_id
            }, room=appointment_room)
        
        return {'success': True, 'message_id': message_id}

    except Exception as e:
        print(f'Error sending message: {str(e)}')
        import traceback
        traceback.print_exc()
        emit('message_error', {'error': str(e)})
        return {'success': False, 'error': str(e)}


@socketio.on('message_read')
def handle_message_read(data):
    """Mark a message (or all messages in appointment) as read by current user and notify sender"""
    if not current_user.is_authenticated:
        return

    appointment_id = data.get('appointment_id')
    message_id = data.get('message_id')

    if not appointment_id:
        return

    # Mark messages as read where sender != current_user
    if message_id:
        try:
            msg = db.session.get(Communication, message_id)
        except Exception:
            msg = db.session.get(Communication, message_id)
        if msg and msg.appointment_id == int(appointment_id) and msg.sender_id != current_user.id:
            msg.is_read = True
            db.session.commit()
            # notify sender
            emit('message_read', {'message_id': msg.id, 'appointment_id': appointment_id}, broadcast=True)
    else:
        msgs = Communication.query.filter_by(appointment_id=appointment_id).filter(Communication.sender_id != current_user.id).all()
        for m in msgs:
            m.is_read = True
        db.session.commit()
        emit('messages_read', {'appointment_id': appointment_id}, broadcast=True)

@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator"""
    if not current_user.is_authenticated:
        return

    appointment_id = data.get('appointment_id')
    appointment_room = f'appointment_{appointment_id}'

    emit('user_typing', {
        'user_id': current_user.id,
        'user_name': safe_display_name(current_user),
        'appointment_id': appointment_id
    }, room=appointment_room, skip_sid=request.sid)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    """Handle stop typing indicator"""
    if not current_user.is_authenticated:
        return

    appointment_id = data.get('appointment_id')
    appointment_room = f'appointment_{appointment_id}'

    emit('user_stop_typing', {
        'user_id': current_user.id,
        'appointment_id': appointment_id
    }, room=appointment_room, skip_sid=request.sid)

# ============================================
# VIDEO CALL EVENTS
# ============================================

@socketio.on('initiate_video_call')
def handle_initiate_video_call(data):
    """Initiate a video call with ringtone and notification"""
    if not current_user.is_authenticated:
        return {'success': False, 'error': 'Not authenticated'}
    
    try:
        appointment_id = data.get('appointment_id')
        appointment = db.session.get(Appointment, appointment_id)
        
        if not appointment:
            emit('call_error', {'error': 'Appointment not found'})
            return
        
        # Get caller and callee information
        caller_name = safe_display_name(current_user)
        caller_role = current_user.role
        
        if current_user.role == 'patient':
            callee_user_id = appointment.doctor.user_id
            callee_role = 'doctor'
        else:
            callee_user_id = appointment.patient.user_id
            callee_role = 'patient'
        
        # CHECK 1: Is callee already on an active call (busy)?
        for active_apt_id, active_call in active_calls.items():
            if active_call['callee_id'] == callee_user_id and active_call['status'] in ['ringing', 'accepted']:
                # Callee is busy on another call
                emit('user_busy', {
                    'appointment_id': appointment_id,
                    'message': f'{caller_name} is currently on another call. Please wait or try again later.',
                    'callee_name': safe_display_name(db.session.get(User, callee_user_id))
                })
                return
        
        # Store call information
        call_info = {
            'appointment_id': appointment_id,
            'caller_id': current_user.id,
            'caller_name': caller_name,
            'caller_role': caller_role,
            'callee_id': callee_user_id,
            'call_type': 'video',
            'start_time': datetime.now(timezone.utc).isoformat(),
            'status': 'ringing'
        }
        
        active_calls[appointment_id] = call_info
        
        # Notify caller that call is ringing
        emit('call_ringing', {
            'appointment_id': appointment_id,
            'call_type': 'video'
        })
        
        # Prepare call notification data (including caller_id)
        call_data = {
            'appointment_id': appointment_id,
            'caller_id': current_user.id,
            'caller_name': caller_name,
            'caller_profile_pic': get_user_profile_picture_url(current_user),
            'caller_role': caller_role,
            'callee_role': callee_role,
            'call_type': 'video',
            'appointment_date': appointment.appointment_date.isoformat(),
            'appointment_time': appointment.appointment_date.strftime('%H:%M'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # CHECK 2: Is callee connected to Socket.IO (online in app)?
        callee_socket_id = user_sockets.get(callee_user_id)
        if callee_socket_id:
            # Callee is online in app - send incoming call notification with ringtone
            emit('incoming_video_call', call_data, room=f'user_{callee_user_id}')
        else:
            # Callee offline from app but may have browser/network access
            # Send browser notification that will appear on top even if app is closed
            emit('browser_notification_video_call', {
                'appointment_id': appointment_id,
                'caller_name': caller_name,
                'caller_role': caller_role,
                'message': f'{caller_name} ({caller_role}) is calling you',
                'notification_type': 'incoming_call'
            }, room=f'user_{callee_user_id}')
        
        # Capture caller id for use inside background tasks (no request context there)
        caller_id = current_user.id

        # Set call timeout (1 minute)
        def call_timeout():
            try:
                # Run DB queries and emits within an application context so background
                # tasks don't error with "Working outside of request context"
                with app.app_context():
                    if appointment_id in active_calls and active_calls[appointment_id]['status'] == 'ringing':
                        # Call timed out - no answer
                        active_calls[appointment_id]['status'] = 'timeout'

                        # Notify caller that call was not answered (use socketio.emit here)
                        if caller_id in user_sockets and user_sockets[caller_id]:
                            socketio.emit('call_ended', {
                                'appointment_id': appointment_id,
                                'reason': 'timeout',
                                'message': 'Call timed out - no answer',
                                'call_type': 'video'
                            }, room=f'user_{caller_id}')

                        # Create missed call notification for callee (whether online or offline)
                        try:
                            callee_user = db.session.get(User, callee_user_id)
                            notif = Notification(
                                user_id=callee_user_id,
                                appointment_id=appointment_id,
                                notification_type='missed_video_call',
                                sender_id=caller_id,
                                title='Missed Video Call',
                                body=f'{safe_display_name(db.session.get(User, caller_id))} called you',
                                call_status='missed'
                            )
                            db.session.add(notif)
                            db.session.commit()
                        except Exception as e:
                            try:
                                app.logger.exception('Error creating missed call notification: %s', e)
                                db.session.rollback()
                            except Exception:
                                pass

                        # Also send Socket.IO missed_call event if callee is online
                        if callee_user_id in user_sockets and user_sockets[callee_user_id]:
                            socketio.emit('missed_call', {
                                'appointment_id': appointment_id,
                                'caller_name': caller_name,
                                'caller_role': caller_role,
                                'call_type': 'video',
                                'timestamp': datetime.now(timezone.utc).isoformat()
                            }, room=f'user_{callee_user_id}')

                        # Clean up
                        if appointment_id in active_calls:
                            del active_calls[appointment_id]
            except Exception as e:
                # Log but don't let background task crash
                print(f'Error in call_timeout for appointment {appointment_id}: {e}')
        
        # Schedule timeout
        socketio.start_background_task(lambda: socketio.sleep(60) or call_timeout())
        
        return {'success': True, 'message': 'Call initiated'}
        
    except Exception as e:
        print(f'Error initiating video call: {str(e)}')
        emit('call_error', {'error': str(e)})
        return {'success': False, 'error': str(e)}

@socketio.on('accept_video_call')
def handle_accept_video_call(data):
    """Accept an incoming video call"""
    if not current_user.is_authenticated:
        return
    
    try:
        appointment_id = data.get('appointment_id')
        
        if appointment_id not in active_calls:
            emit('call_error', {'error': 'Call not found'})
            return
        
        call_info = active_calls[appointment_id]
        
        # Update call status
        call_info['status'] = 'accepted'
        call_info['accepted_time'] = datetime.now(timezone.utc).isoformat()
        
        # Notify both parties that call is connected using per-user rooms
        call_data = {
            'appointment_id': appointment_id,
            'caller_id': call_info['caller_id'],
            'callee_id': current_user.id,
            'call_type': 'video'
        }
        
        # Notify caller
        if call_info['caller_id'] in user_sockets and user_sockets[call_info['caller_id']]:
            emit('video_call_accepted', call_data, room=f'user_{call_info["caller_id"]}')
        
        # Notify callee
        if current_user.id in user_sockets and user_sockets[current_user.id]:
            emit('video_call_accepted', call_data, room=f'user_{current_user.id}')
        
        print(f'Video call accepted for appointment {appointment_id}')
        
    except Exception as e:
        print(f'Error accepting video call: {str(e)}')
        emit('call_error', {'error': str(e)})

@socketio.on('reject_video_call')
def handle_reject_video_call(data):
    """Reject an incoming video call"""
    if not current_user.is_authenticated:
        return
    
    try:
        appointment_id = data.get('appointment_id')
        
        if appointment_id not in active_calls:
            return
        
        call_info = active_calls[appointment_id]
        
        # Notify caller that call was rejected
        caller_socket_id = user_sockets.get(call_info['caller_id'])
        
        if caller_socket_id:
            emit('video_call_rejected', {
                'appointment_id': appointment_id,
                'reason': 'declined',
                'message': 'Call was declined'
            }, room=caller_socket_id)
        
        # Clean up
        del active_calls[appointment_id]
        
        print(f'Video call rejected for appointment {appointment_id}')
        
    except Exception as e:
        print(f'Error rejecting video call: {str(e)}')

@socketio.on('end_video_call')
def handle_end_video_call(data):
    """End a video call"""
    if not current_user.is_authenticated:
        return
    
    try:
        appointment_id = data.get('appointment_id')
        
        if appointment_id not in active_calls:
            return
        
        call_info = active_calls[appointment_id]
        
        # Notify both parties that call ended
        # Support multiple possible key names in call_info (legacy variations)
        caller_id = call_info.get('caller') or call_info.get('caller_id') or call_info.get('caller_user_id')
        callee_id = call_info.get('callee') or call_info.get('callee_id') or call_info.get('callee_user_id')

        caller_sockets = user_sockets.get(caller_id)
        callee_sockets = user_sockets.get(callee_id)

        # Include appointment doctor and patient user ids to help client-side redirects
        doctor_user_id = None
        patient_user_id = None
        try:
            apt = db.session.get(Appointment, appointment_id)
            if apt:
                try:
                    doc = db.session.get(Doctor, apt.doctor_id)
                    if doc:
                        doctor_user_id = getattr(doc, 'user_id', None)
                except Exception:
                    doctor_user_id = None
                try:
                    pat = db.session.get(Patient, apt.patient_id)
                    if pat:
                        patient_user_id = getattr(pat, 'user_id', None)
                except Exception:
                    patient_user_id = None
        except Exception:
            apt = None
            app.logger.exception('Failed to load appointment for end_video_call')

        end_data = {
            'appointment_id': appointment_id,
            'ended_by': current_user.id,
            'reason': data.get('reason', 'ended_by_user'),
            'message': data.get('message', 'Call ended'),
            'doctor_user_id': doctor_user_id,
            'patient_user_id': patient_user_id
        }

        # Emit to all socket ids if stored as list, or single sid
        def emit_to_sockets(sockets, payload):
            try:
                if not sockets:
                    return
                if isinstance(sockets, list):
                    for sid in sockets:
                        emit('video_call_ended', payload, room=sid)
                else:
                    emit('video_call_ended', payload, room=sockets)
            except Exception:
                pass

        # Only the doctor may end the call for both participants. If the current user
        # is not the doctor, treat this as a local leave and do not end the call for everyone.
        try:
            is_doctor_ender = (doctor_user_id is not None and current_user.id == int(doctor_user_id))
        except Exception:
            is_doctor_ender = False

        if not is_doctor_ender:
            # Patient or other participant left; notify room that user left but don't end call
            try:
                emit('user_left_video_room', {'user_id': current_user.id, 'appointment_id': appointment_id}, room=f'video_call_{appointment_id}')
            except Exception:
                pass
            return

        # If the doctor is ending the call, update appointment status to 'incomplete' if it wasn't marked completed
        try:
            if apt:
                if getattr(apt, 'status', None) != 'completed':
                    apt.status = 'incomplete'
                    db.session.add(apt)
                    db.session.commit()
                    # Audit log: appointment marked incomplete by doctor hangup
                    try:
                        audit = AuditLog(user_id=current_user.id, action='appointment_marked_incomplete', description=f'Doctor ended call for appointment {appointment_id} without marking complete', ip_address=request.remote_addr)
                        db.session.add(audit)
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
                    app.logger.info('Appointment %s marked as incomplete because doctor ended call without marking complete', appointment_id)
        except Exception:
            db.session.rollback()
            app.logger.exception('Failed to mark appointment incomplete on doctor end_video_call')

        emit_to_sockets(caller_sockets, end_data)
        emit_to_sockets(callee_sockets, end_data)

        # Clean up
        if appointment_id in active_calls:
            del active_calls[appointment_id]

        app.logger.info('Video call ended for appointment %s by user %s', appointment_id, current_user.id)
        
    except Exception as e:
        app.logger.exception('Error ending video call')

@socketio.on('join_video_room')
def handle_join_video_room(data):
    """Join video call room for WebRTC negotiation"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    room_name = f'video_call_{appointment_id}'
    
    join_room(room_name)
    
    emit('user_joined_video_room', {
        'user_id': current_user.id,
        'user_name': safe_display_name(current_user),
        'appointment_id': appointment_id
    }, room=room_name, skip_sid=request.sid)

@socketio.on('leave_video_room')
def handle_leave_video_room(data):
    """Leave video call room"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    room_name = f'video_call_{appointment_id}'
    
    leave_room(room_name)
    
    emit('user_left_video_room', {
        'user_id': current_user.id,
        'appointment_id': appointment_id
    }, room=room_name, skip_sid=request.sid)


# Doctor marks consultation complete
@app.route('/api/appointments/<int:appointment_id>/complete', methods=['POST'])
@login_required
def mark_appointment_complete(appointment_id):
    try:
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return jsonify({'error': 'appointment_not_found'}), 404

        # Only the doctor for this appointment may mark it complete
        try:
            doc = db.session.get(Doctor, appointment.doctor_id)
            doctor_user_id = getattr(doc, 'user_id', None) if doc else None
        except Exception:
            doctor_user_id = None

        if current_user.id != doctor_user_id:
            return jsonify({'error': 'forbidden'}), 403

        # Optional notes may be provided by the doctor
        data = request.get_json(silent=True) or {}
        notes = data.get('notes') if isinstance(data, dict) else None
        if notes is not None:
            try:
                appointment.notes = notes
            except Exception:
                pass

        appointment.status = 'completed'
        appointment.call_status = 'ended'
        db.session.add(appointment)
        db.session.commit()

        # Audit log: appointment completed by doctor
        try:
            audit = AuditLog(user_id=current_user.id, action='appointment_completed', description=f'Doctor marked appointment {appointment_id} complete', ip_address=request.remote_addr)
            db.session.add(audit)
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Notify patient and doctor sockets if present
        try:
            patient = db.session.get(Patient, appointment.patient_id)
            patient_user_id = getattr(patient, 'user_id', None) if patient else None
            payload = {'appointment_id': appointment_id, 'status': 'completed'}
            if doctor_user_id:
                socketio.emit('appointment_marked_complete', payload, room=f'user_{doctor_user_id}')
            if patient_user_id:
                socketio.emit('appointment_marked_complete', payload, room=f'user_{patient_user_id}')
        except Exception:
            pass

        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to mark appointment complete')
        return jsonify({'success': False, 'error': str(e)}), 500

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    """Handle WebRTC offer"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    room_name = f'video_call_{appointment_id}'
    
    emit('webrtc_offer', {
        'appointment_id': appointment_id,
        'offer': data.get('offer'),
        'sender_id': current_user.id
    }, room=room_name, skip_sid=request.sid)

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    """Handle WebRTC answer"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    room_name = f'video_call_{appointment_id}'
    
    emit('webrtc_answer', {
        'appointment_id': appointment_id,
        'answer': data.get('answer'),
        'sender_id': current_user.id
    }, room=room_name, skip_sid=request.sid)

@socketio.on('webrtc_ice_candidate')
def handle_webrtc_ice_candidate(data):
    """Handle WebRTC ICE candidate"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    room_name = f'video_call_{appointment_id}'
    
    emit('webrtc_ice_candidate', {
        'appointment_id': appointment_id,
        'candidate': data.get('candidate'),
        'sender_id': current_user.id
    }, room=room_name, skip_sid=request.sid)

# ============================================================================
# ENHANCED SOCKET.IO HANDLERS FOR NEW COMMUNICATION MODELS
# ============================================================================

@socketio.on('presence:update')
def handle_presence_update(data):
    """Handle presence updates and persist to UserPresence model"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        status = data.get('status', 'online')  # online, away, idle, busy, offline, do_not_disturb
        current_call_id = data.get('current_call_id')
        current_appointment_id = data.get('current_appointment_id')
        
        # Upsert UserPresence record
        presence = UserPresence.query.filter_by(user_id=current_user.id).first()
        if not presence:
            presence = UserPresence(user_id=current_user.id)
        
        presence.status = status
        presence.current_call_id = current_call_id
        presence.current_appointment_id = current_appointment_id
        presence.last_heartbeat = datetime.now(timezone.utc)
        presence.last_seen = datetime.now(timezone.utc)
        
        db.session.add(presence)
        db.session.commit()
        
        # Broadcast presence update to all connected clients
        emit('presence:updated', {
            'user_id': current_user.id,
            'status': status,
            'last_seen': presence.last_seen.isoformat(),
            'current_call_id': current_call_id,
            'current_appointment_id': current_appointment_id
        }, broadcast=True)
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Presence update failed: {str(e)}'})


@socketio.on('chat:message')
def handle_chat_message(data):
    """Handle chat messages and persist to Message/Conversation models"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        conversation_id = data.get('conversation_id')
        body = data.get('body', '').strip()
        message_type = data.get('message_type', 'text')  # text, image, file, voice_note
        call_id = data.get('call_id')  # optional - for in-call messages
        
        if not body and message_type == 'text':
            emit('error', {'message': 'Message body cannot be empty'})
            return
        
        # Get or create conversation
        conversation = Conversation.query.filter_by(conversation_id=conversation_id).first()
        if not conversation:
            # Create new conversation
            conversation = Conversation(
                conversation_id=str(uuid4()),
                participant_ids=json.dumps([current_user.id]),
                conversation_type='direct',
                is_active=True
            )
            db.session.add(conversation)
            db.session.flush()
        
        # Create message record
        message = Message(
            message_id=str(uuid4()),
            conversation_id=conversation.id,
            sender_id=current_user.id,
            encrypted_body=body,  # In production, this should be encrypted
            message_type=message_type,
            in_call=bool(call_id),
            call_id=call_id,
            status='sent'
        )
        
        db.session.add(message)
        
        # Update conversation's last_message_at
        conversation.last_message_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        # Broadcast message to conversation participants via Socket.IO
        socketio.emit('chat:message', {
            'message_id': message.message_id,
            'conversation_id': conversation.conversation_id,
            'sender_id': current_user.id,
            'sender_name': safe_display_name(current_user) if hasattr(current_user, '__dict__') else str(current_user.id),
            'body': body,
            'message_type': message_type,
            'status': 'sent',
            'created_at': message.created_at.isoformat() if message.created_at else datetime.now(timezone.utc).isoformat(),
            'in_call': bool(call_id)
        }, room=f'conversation_{conversation_id}')
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Message send failed: {str(e)}'})


@socketio.on('chat:delivered')
def handle_message_delivered(data):
    """Mark message as delivered"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        message_id = data.get('message_id')
        message = Message.query.filter_by(message_id=message_id).first()
        
        if message:
            message.status = 'delivered'
            message.delivered_at = datetime.now(timezone.utc)
            db.session.commit()
            
            socketio.emit('chat:delivered', {
                'message_id': message_id,
                'status': 'delivered',
                'delivered_at': message.delivered_at.isoformat()
            }, broadcast=True)
    except Exception as e:
        db.session.rollback()


@socketio.on('chat:read')
def handle_message_read(data):
    """Mark message as read"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        message_id = data.get('message_id')
        message = Message.query.filter_by(message_id=message_id).first()
        
        if message:
            message.status = 'read'
            message.read_at = datetime.now(timezone.utc)
            db.session.commit()
            
            socketio.emit('chat:read', {
                'message_id': message_id,
                'status': 'read',
                'read_at': message.read_at.isoformat()
            }, broadcast=True)
    except Exception as e:
        db.session.rollback()


@socketio.on('call:initiate')
def handle_call_initiate_enhanced(data):
    """Enhanced call initiation that persists to CallHistory"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        caller_id = current_user.id
        callee_id = data.get('callee_id')
        appointment_id = data.get('appointment_id')
        call_type = data.get('call_type', 'video')  # video or voice
        
        if not callee_id:
            emit('error', {'message': 'Callee ID is required'})
            return
        
        # Create CallHistory record
        call_history = CallHistory(
            call_id=str(uuid4()),
            appointment_id=appointment_id,
            caller_id=caller_id,
            callee_id=callee_id,
            call_type=call_type,
            initiated_at=datetime.now(timezone.utc),
            status='initiated'
        )
        
        db.session.add(call_history)
        db.session.commit()
        
        # Emit to existing handlers for backward compatibility
        emit('call_initiated', {
            'call_id': call_history.call_id,
            'caller_id': caller_id,
            'callee_id': callee_id,
            'appointment_id': appointment_id,
            'call_type': call_type,
            'initiated_at': call_history.initiated_at.isoformat(),
            'status': 'initiated'
        }, room=f'user_{callee_id}')
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Call initiation failed: {str(e)}'})


@socketio.on('call:accept')
def handle_call_accept_enhanced(data):
    """Enhanced call acceptance that updates CallHistory"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        call_id = data.get('call_id')
        
        call_history = CallHistory.query.filter_by(call_id=call_id).first()
        if not call_history:
            emit('error', {'message': 'Call not found'})
            return
        
        # Update call status
        call_history.accepted_at = datetime.now(timezone.utc)
        call_history.status = 'accepted'
        call_history.room_id = f'call_{call_id}'
        
        db.session.commit()
        
        emit('call_accepted', {
            'call_id': call_id,
            'accepted_at': call_history.accepted_at.isoformat(),
            'status': 'accepted',
            'room_id': call_history.room_id
        }, broadcast=True)
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Call acceptance failed: {str(e)}'})


@socketio.on('call:end')
def handle_call_end_enhanced(data):
    """Enhanced call end that finalizes CallHistory record"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        call_id = data.get('call_id')
        reason = data.get('reason', 'user_hangup')  # user_hangup, callee_declined, missed, busy, network_error
        duration = data.get('duration', 0)  # seconds
        
        call_history = CallHistory.query.filter_by(call_id=call_id).first()
        if not call_history:
            emit('error', {'message': 'Call not found'})
            return
        
        # Update call record
        call_history.ended_at = datetime.now(timezone.utc)
        call_history.status = 'ended'
        call_history.end_reason = reason
        call_history.duration = duration
        
        db.session.commit()
        
        emit('call_ended', {
            'call_id': call_id,
            'ended_at': call_history.ended_at.isoformat(),
            'status': 'ended',
            'reason': reason,
            'duration': duration
        }, broadcast=True)

        # Create notifications for missed/declined/busy events
        try:
            if reason in ('missed', 'unanswered', 'callee_declined', 'busy', 'connection_failed'):
                # Notify both participants about the end reason
                recipients = set()
                if call_history.caller_id:
                    recipients.add(call_history.caller_id)
                if call_history.callee_id:
                    recipients.add(call_history.callee_id)

                for uid in recipients:
                    try:
                        n = Notification(
                            user_id=uid,
                            appointment_id=call_history.appointment_id,
                            notification_type=f'missed_{call_history.call_type}' if reason == 'missed' else call_history.call_type,
                            sender_id=current_user.id,
                            title='Call update',
                            body=f'Call {call_history.call_type} ended: {reason}',
                            is_read=False,
                            call_status=reason
                        )
                        db.session.add(n)
                    except Exception:
                        db.session.rollback()
                db.session.commit()
        except Exception:
            db.session.rollback()
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Call end failed: {str(e)}'})


@socketio.on('quality:metrics')
def handle_quality_metrics(data):
    """Handle call quality metrics submission"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        call_id = data.get('call_id')
        rtt = data.get('rtt')
        packet_loss = data.get('packet_loss')
        jitter = data.get('jitter')
        audio_bitrate = data.get('audio_bitrate')
        video_bitrate = data.get('video_bitrate')
        video_resolution = data.get('video_resolution')
        video_framerate = data.get('video_framerate')
        cpu_usage = data.get('cpu_usage')
        memory_usage = data.get('memory_usage')
        audio_quality = data.get('audio_quality', 'good')
        video_quality = data.get('video_quality', 'good')
        
        # Get call history for reference
        call_history = CallHistory.query.filter_by(call_id=call_id).first()
        if not call_history:
            emit('error', {'message': 'Call not found'})
            return
        
        # Create quality metrics record
        metrics = CallQualityMetrics(
            call_id=call_id,
            user_id=current_user.id,
            rtt=rtt,
            packet_loss=packet_loss,
            jitter=jitter,
            audio_bitrate=audio_bitrate,
            video_bitrate=video_bitrate,
            video_resolution=video_resolution,
            video_framerate=video_framerate,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            audio_quality=audio_quality,
            video_quality=video_quality,
            timestamp=datetime.now(timezone.utc)
        )
        
        db.session.add(metrics)
        
        # Update call_history quality_metrics JSON field
        try:
            existing_metrics = json.loads(call_history.quality_metrics or '{}')
        except:
            existing_metrics = {}
        
        existing_metrics[str(current_user.id)] = {
            'rtt': rtt,
            'packet_loss': packet_loss,
            'jitter': jitter,
            'audio_bitrate': audio_bitrate,
            'video_bitrate': video_bitrate,
            'audio_quality': audio_quality,
            'video_quality': video_quality
        }
        
        call_history.quality_metrics = json.dumps(existing_metrics)
        
        db.session.commit()
        
        emit('quality:recorded', {
            'call_id': call_id,
            'user_id': current_user.id,
            'audio_quality': audio_quality,
            'video_quality': video_quality,
            'rtt': rtt,
            'packet_loss': packet_loss
        }, broadcast=True)
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Quality metrics recording failed: {str(e)}'})

# Add this route for checking call status
@app.route('/api/call/status/<int:appointment_id>')
@login_required
def get_call_status(appointment_id):
    """Get current call status for an appointment"""
    call_info = active_calls.get(appointment_id, {})
    return jsonify(call_info)

# Add this route for getting missed calls
@app.route('/api/missed_calls')
@login_required
def get_missed_calls():
    """Get missed calls for current user"""
    # This would typically query a database table for missed calls
    # For now, return empty array - implementation would depend on your data model
    return jsonify([])

@socketio.on('call_chat_message')
def handle_call_chat_message(data):
    """Handle chat messages during call"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    appointment = db.session.get(Appointment, appointment_id)
    
    if not appointment or not verify_appointment_access(appointment, current_user):
        return
    
    # Broadcast chat message to all in the call
    emit('call_chat_message', {
        'appointment_id': appointment_id,
        'message': data.get('message'),
        'sender_id': current_user.id,
        'sender_name': safe_display_name(current_user),
        'timestamp': datetime.utcnow().isoformat()
    }, room=f'video_call_{appointment_id}')

@socketio.on('call_file_share')
def handle_call_file_share(data):
    """Handle file sharing during call"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    appointment = db.session.get(Appointment, appointment_id)
    
    if not appointment or not verify_appointment_access(appointment, current_user):
        return
    
    # Broadcast file share to all in the call
    emit('call_file_share', {
        'appointment_id': appointment_id,
        'file_name': data.get('file_name'),
        'file_data': data.get('file_data'),
        'file_size': data.get('file_size'),
        'sender_id': current_user.id,
        'sender_name': safe_display_name(current_user),
        'timestamp': datetime.utcnow().isoformat()
    }, room=f'video_call_{appointment_id}', skip_sid=request.sid)

@socketio.on('call_user_info')
def handle_call_user_info(data):
    """Handle user profile info during call"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    appointment = db.session.get(Appointment, appointment_id)
    
    if not appointment or not verify_appointment_access(appointment, current_user):
        return
    
    # Broadcast user info to all in the call
    emit('call_user_info', {
        'appointment_id': appointment_id,
        'user_id': data.get('user_id'),
        'first_name': data.get('first_name'),
        'last_name': data.get('last_name'),
        'profile_picture_url': data.get('profile_picture_url'),
        'timestamp': datetime.utcnow().isoformat()
    }, room=f'video_call_{appointment_id}', skip_sid=request.sid)

@socketio.on('end_call')
def handle_end_call(data):
    """Handle call end"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    appointment = db.session.get(Appointment, appointment_id)
    
    if not appointment or not verify_appointment_access(appointment, current_user):
        return
    
    # Notify other participant that call ended
    emit('call_ended', {
        'appointment_id': appointment_id,
        'ended_by': current_user.id,
        'ended_by_name': safe_display_name(current_user)
    }, room=f'video_call_{appointment_id}', skip_sid=request.sid)

# ============================================
# VOICE CALL EVENTS
# ============================================

@socketio.on('initiate_voice_call')
def handle_initiate_voice_call(data):
    """Initiate a voice call"""
    if not current_user.is_authenticated:
        return {'success': False, 'error': 'Not authenticated'}
    
    try:
        appointment_id = data.get('appointment_id')
        appointment = db.session.get(Appointment, appointment_id)
        
        if not appointment:
            emit('call_error', {'error': 'Appointment not found'})
            return
        
        # Get caller and callee information
        caller_name = safe_display_name(current_user)
        caller_role = current_user.role
        
        if current_user.role == 'patient':
            callee_user_id = appointment.doctor.user_id
            callee_role = 'doctor'
        else:
            callee_user_id = appointment.patient.user_id
            callee_role = 'patient'
        
        # Check if callee is on another call (busy)
        is_busy = any(c.get('appointment_id') != appointment_id and 
                     c.get('callee_id') == callee_user_id and 
                     c.get('status') in ['ringing', 'accepted'] 
                     for c in active_calls.values())
        
        if is_busy:
            # Notify caller that callee is busy
            busy_notification = {
                'appointment_id': appointment_id,
                'status': 'busy',
                'message': f'{caller_name} is currently on another call',
                'callee_name': caller_name,
                'recommendation': 'Please wait or end this attempt'
            }
            emit('call_failed_busy', busy_notification, room=f'user_{current_user.id}')
            
            # Create notification for caller
            try:
                notif = Notification(
                    user_id=current_user.id,
                    appointment_id=appointment_id,
                    notification_type='busy_voice_call',
                    sender_id=callee_user_id,
                    title='User Busy',
                    body=f'{caller_name} is currently on another call',
                    call_status='busy'
                )
                db.session.add(notif)
                db.session.commit()
            except Exception:
                db.session.rollback()
            return {'success': False, 'error': 'User is busy'}
        
        # Store call information
        call_info = {
            'appointment_id': appointment_id,
            'caller_id': current_user.id,
            'caller_name': caller_name,
            'caller_role': caller_role,
            'callee_id': callee_user_id,
            'call_type': 'voice',
            'start_time': datetime.now(timezone.utc).isoformat(),
            'status': 'ringing'
        }
        
        active_calls[appointment_id] = call_info
        
        # Prepare call notification data
        call_data = {
            'appointment_id': appointment_id,
            'caller_id': current_user.id,
            'caller_name': caller_name,
            'caller_profile_pic': get_user_profile_picture_url(current_user),
            'caller_role': caller_role,
            'callee_role': callee_role,
            'callee_profile_pic': None,
            'call_type': 'voice',
            'appointment_date': appointment.appointment_date.isoformat(),
            'appointment_time': appointment.appointment_date.strftime('%H:%M'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Try to include callee profile picture URL for client rendering
        try:
            callee_user = db.session.get(User, callee_user_id)
            if callee_user:
                call_data['callee_profile_pic'] = get_user_profile_picture_url(callee_user)
        except Exception:
            pass
        
        # Notify caller that call is ringing
        emit('call_ringing', {
            'appointment_id': appointment_id,
            'call_type': 'voice'
        })
        
        # Check if callee is online
        callee_is_online = callee_user_id in user_sockets and bool(user_sockets[callee_user_id])
        
        if callee_is_online:
            # Send incoming call notification to callee
            emit('incoming_voice_call', call_data, room=f'user_{callee_user_id}')
            
            # Set call timeout (60 seconds)
            def voice_call_timeout():
                try:
                    with app.app_context():
                        if appointment_id in active_calls and active_calls[appointment_id]['status'] == 'ringing':
                            active_calls[appointment_id]['status'] = 'unanswered'

                            # Notify caller of missed call
                            socketio.emit('voice_call_unanswered', {
                                'appointment_id': appointment_id,
                                'message': f'{caller_name} did not answer',
                                'status': 'unanswered'
                            }, room=f'user_{current_user.id}')

                            # Create missed call notification for callee
                            try:
                                notif = Notification(
                                    user_id=callee_user_id,
                                    appointment_id=appointment_id,
                                    notification_type='missed_voice_call',
                                    sender_id=current_user.id,
                                    title='Missed Voice Call',
                                    body=f'{caller_name} called you',
                                    call_status='missed'
                                )
                                db.session.add(notif)
                                db.session.commit()
                            except Exception:
                                try:
                                    db.session.rollback()
                                except Exception:
                                    pass

                            # Clean up
                            active_calls.pop(appointment_id, None)
                except Exception:
                    pass

            socketio.start_background_task(lambda: (socketio.sleep(60), voice_call_timeout()))
        else:
            # Callee is offline but try to reach via web/browser
            offline_notification = {
                'appointment_id': appointment_id,
                'status': 'offline_attempting',
                'message': f'{caller_name} is currently offline',
                'recommendation': 'Attempting to reach via web/browser...'
            }
            emit('call_ringing', offline_notification, room=f'user_{current_user.id}')
            
            # Extended timeout for offline users (90 seconds)
            def voice_call_offline_timeout():
                try:
                    with app.app_context():
                        if appointment_id in active_calls and active_calls[appointment_id]['status'] == 'ringing':
                            active_calls[appointment_id]['status'] = 'connection_failed'

                            # Notify caller of connection failure
                            socketio.emit('voice_call_connection_failed', {
                                'appointment_id': appointment_id,
                                'message': f'Unable to connect to {caller_name}',
                                'status': 'connection_failed'
                            }, room=f'user_{current_user.id}')

                            # Create notification
                            try:
                                notif = Notification(
                                    user_id=current_user.id,
                                    appointment_id=appointment_id,
                                    notification_type='voice_call_failed',
                                    sender_id=callee_user_id,
                                    title='Call Connection Failed',
                                    body=f'Unable to reach {caller_name}',
                                    call_status='connection_failed'
                                )
                                db.session.add(notif)
                                db.session.commit()
                            except Exception:
                                try:
                                    db.session.rollback()
                                except Exception:
                                    pass

                            # Clean up
                            active_calls.pop(appointment_id, None)
                except Exception:
                    pass

            socketio.start_background_task(lambda: (socketio.sleep(90), voice_call_offline_timeout()))
        
        return {'success': True, 'message': 'Call initiated'}
        
    except Exception as e:
        print(f'Error initiating voice call: {str(e)}')
        emit('call_error', {'error': str(e)})
        return {'success': False, 'error': str(e)}

@socketio.on('accept_voice_call')
def handle_accept_voice_call(data):
    """Accept an incoming voice call"""
    if not current_user.is_authenticated:
        return
    
    try:
        appointment_id = data.get('appointment_id')
        
        if appointment_id not in active_calls:
            emit('call_error', {'error': 'Call not found'})
            return
        
        call_info = active_calls[appointment_id]
        
        # Check if caller has another active call (call collision)
        has_active_call = any(c.get('appointment_id') != appointment_id and 
                             c.get('caller_id') == call_info['caller_id'] and 
                             c.get('status') == 'accepted' 
                             for c in active_calls.values())
        
        if has_active_call:
            # Reject if caller is busy too
            emit('call_error', {'error': 'caller_has_active_call'})
            return
        
        # Update call status
        call_info['status'] = 'accepted'
        call_info['accepted_time'] = datetime.now(timezone.utc).isoformat()
        call_info['callee_id'] = current_user.id
        
        # Notify both parties that call is connected
        call_data = {
            'appointment_id': appointment_id,
            'caller_id': call_info['caller_id'],
            'callee_id': current_user.id,
            'call_type': 'voice'
        }
        
        # Create accepted call notification for caller
        try:
            notif = Notification(
                user_id=call_info['caller_id'],
                appointment_id=appointment_id,
                notification_type='voice_call_accepted',
                sender_id=current_user.id,
                title='Call Accepted',
                body=f'{call_info.get("caller_name", "User")} accepted your voice call',
                call_status='accepted'
            )
            db.session.add(notif)
            db.session.commit()
        except Exception:
            db.session.rollback()
        
        emit('voice_call_accepted', call_data, room=f'user_{call_info["caller_id"]}')
        emit('voice_call_accepted', call_data, room=f'user_{current_user.id}')
        
        print(f'Voice call accepted for appointment {appointment_id}')
        
    except Exception as e:
        print(f'Error accepting voice call: {str(e)}')
        emit('call_error', {'error': str(e)})

@socketio.on('end_voice_call')
def handle_end_voice_call(data):
    """End a voice call"""
    if not current_user.is_authenticated:
        return
    
    try:
        appointment_id = data.get('appointment_id')
        
        if appointment_id not in active_calls:
            return
        
        call_info = active_calls[appointment_id]
        # Determine appointment and doctor/patient user ids
        try:
            apt = db.session.get(Appointment, appointment_id)
        except Exception:
            apt = None

        doctor_user_id = None
        patient_user_id = None
        try:
            if apt:
                doc = db.session.get(Doctor, apt.doctor_id)
                if doc:
                    doctor_user_id = getattr(doc, 'user_id', None)
                pat = db.session.get(Patient, apt.patient_id)
                if pat:
                    patient_user_id = getattr(pat, 'user_id', None)
        except Exception:
            pass

        # Only the doctor may end the call for all participants
        try:
            is_doctor_ender = (doctor_user_id is not None and current_user.id == int(doctor_user_id))
        except Exception:
            is_doctor_ender = False

        if not is_doctor_ender:
            # Non-doctor leaves locally: notify room/user and do not end for others
            try:
                emit('user_left_appointment', {'user_id': current_user.id, 'appointment_id': appointment_id}, room=f'appointment_{appointment_id}')
            except Exception:
                pass
            return

        # Doctor is ending the call for everyone: update appointment to 'incomplete' if not completed
        try:
            if apt and getattr(apt, 'status', None) != 'completed':
                apt.status = 'incomplete'
                db.session.add(apt)
                db.session.commit()
                # Audit log for incomplete
                try:
                    audit = AuditLog(user_id=current_user.id, action='appointment_marked_incomplete', description=f'Doctor ended voice call for appointment {appointment_id} without marking complete', ip_address=request.remote_addr)
                    db.session.add(audit)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
        except Exception:
            db.session.rollback()
            app.logger.exception('Failed to mark appointment incomplete on doctor end_voice_call')

        # Update call info and create notification
        call_info['status'] = 'ended'
        call_info['ended_time'] = datetime.now(timezone.utc).isoformat()
        call_info['ended_by'] = current_user.id

        other_user_id = call_info['caller_id'] if current_user.id != call_info['caller_id'] else call_info.get('callee_id')
        try:
            notif = Notification(
                user_id=other_user_id,
                appointment_id=appointment_id,
                notification_type='voice_call_ended',
                sender_id=current_user.id,
                title='Voice Call Ended',
                body=f'Voice call has ended',
                call_status='ended'
            )
            db.session.add(notif)
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Notify both parties
        call_ended_data = {
            'appointment_id': appointment_id,
            'ended_by': current_user.id,
            'call_type': 'voice'
        }

        emit('voice_call_ended', call_ended_data, room=f'user_{call_info["caller_id"]}')
        if call_info.get('callee_id'):
            emit('voice_call_ended', call_ended_data, room=f'user_{call_info["callee_id"]}')

        # Clean up
        active_calls.pop(appointment_id, None)
        app.logger.info('Voice call ended for appointment %s by user %s', appointment_id, current_user.id)
        
    except Exception as e:
        print(f'Error ending voice call: {str(e)}')

# ============================================
# ROOM MANAGEMENT
# ============================================

@socketio.on('join_appointment')
def handle_join_appointment(data):
    """Join appointment communication room"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    appointment_room = f'appointment_{appointment_id}'
    
    join_room(appointment_room)
    emit('user_joined', {
        'user_id': current_user.id,
        'user_name': safe_display_name(current_user),
        'appointment_id': appointment_id
    }, room=appointment_room)
    
    print(f'User {current_user.id} joined appointment room {appointment_id}')

@socketio.on('leave_appointment')
def handle_leave_appointment(data):
    """Leave appointment communication room"""
    if not current_user.is_authenticated:
        return
    
    appointment_id = data.get('appointment_id')
    appointment_room = f'appointment_{appointment_id}'
    
    leave_room(appointment_room)
    emit('user_left', {
        'user_id': current_user.id,
        'appointment_id': appointment_id
    }, room=appointment_room)
    
    print(f'User {current_user.id} left appointment room {appointment_id}')

# ============================================
# NOTIFICATION EVENTS (WITH SOUND)
# ============================================

@socketio.on('send_notification')
def handle_send_notification(data):
    """Send a notification with optional sound"""
    if not current_user.is_authenticated:
        return
    
    try:
        recipient_id = data.get('recipient_id')
        notification_type = data.get('type')  # message, voice_call, video_call
        title = data.get('title')
        body = data.get('body')
        sound_enabled = data.get('sound_enabled', True)
        appointment_id = data.get('appointment_id')
        
        # Create notification in database
        notification = Notification(
            user_id=recipient_id,
            notification_type=notification_type,
            sender_id=current_user.id,
            title=title,
            body=body,
            sound_enabled=sound_enabled,
            appointment_id=appointment_id
        )
        db.session.add(notification)
        db.session.commit()
        
        # Send to recipient if online
        recipient_socket_id = user_sockets.get(recipient_id)
        if recipient_socket_id:
            emit('notification_received', {
                'notification_id': notification.id,
                'type': notification_type,
                'title': title,
                'body': body,
                'sender_id': current_user.id,
                'sender_name': safe_display_name(current_user),
                'sound_enabled': sound_enabled,
                'appointment_id': appointment_id,
                'timestamp': notification.created_at.isoformat()
            }, room=recipient_socket_id)
            
            return {'success': True, 'sent_immediately': True}
        else:
            return {'success': True, 'sent_immediately': False, 'queued': True}
    
    except Exception as e:
        print(f'Error sending notification: {str(e)}')
        emit('notification_error', {'error': str(e)})
        return {'success': False, 'error': str(e)}

@socketio.on('play_notification_sound')
def handle_play_notification_sound(data):
    """Trigger sound notification on client"""
    if not current_user.is_authenticated:
        return
    
    notification_type = data.get('type')  # message, voice_call, video_call
    
    # Broadcast sound event to the specific user
    recipient_id = data.get('recipient_id')
    recipient_socket_id = user_sockets.get(recipient_id)
    
    if recipient_socket_id:
        emit('play_sound', {
            'type': notification_type,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=recipient_socket_id)

@socketio.on('mark_notification_read')
def handle_mark_notification_read(data):
    """Mark notification as read"""
    if not current_user.is_authenticated:
        return
    
    try:
        notification_id = data.get('notification_id')
        notification = db.session.get(Notification, notification_id)
        
        if notification and notification.user_id == current_user.id:
            notification.is_read = True
            db.session.commit()
            return {'success': True}
    
    except Exception as e:
        print(f'Error marking notification as read: {str(e)}')
    
    return {'success': False}

@socketio.on('join_admin_chat')
def handle_join_admin_chat(data):
    """Join admin chat room"""
    if not current_user.is_authenticated:
        return {'error': 'Not authenticated'}
    
    # Only allow patients and doctors to contact admins
    if current_user.role not in ['patient', 'doctor']:
        return {'error': 'Access denied'}
    
    admin_id = data.get('admin_id')
    user_id = data.get('user_id')
    user_role = data.get('user_role')
    
    # Verify admin exists
    admin = db.session.get(User, admin_id)
    if not admin or admin.role != 'admin':
        return {'error': 'Invalid admin'}
    
    # Create room name for this conversation
    room_name = f'admin_chat_{min(user_id, admin_id)}_{max(user_id, admin_id)}'
    
    # Join the room
    join_room(room_name)
    
    # Notify admin that someone is chatting with them
    socketio.emit('admin_chat_started', {
        'user_id': user_id,
        'user_name': f"{current_user.first_name} {current_user.last_name}",
        'user_role': user_role,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }, room=room_name)
    
    return {'success': True, 'room': room_name}

@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    """Get user's notifications"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        include_read = request.args.get('include_read', 'false').lower() == 'true'
        # sanitize paging
        if per_page <= 0:
            per_page = 20
        if page <= 0:
            page = 1

        query = Notification.query.filter_by(user_id=current_user.id)
        if not include_read:
            query = query.filter_by(is_read=False)

        total = query.count()
        pages = max(1, math.ceil(total / per_page))
        notifications = query.order_by(Notification.created_at.desc()).offset((page-1)*per_page).limit(per_page).all()

        data = [{
            'id': n.id,
            'type': n.notification_type,
            'title': n.title,
            'body': n.body,
            'sender_id': n.sender_id,
            'sender_name': safe_display_name(n.sender) if n.sender else None,
            'appointment_id': n.appointment_id,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat()
        } for n in notifications]

        return jsonify({'success': True, 'notifications': data, 'total': total, 'page': page, 'pages': pages})
    
    except Exception as e:
        import traceback
        app.logger.error('Error in get_notifications: %s', e)
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a single notification as read"""
    try:
        notification = db.session.get(Notification, notification_id)
        
        if not notification or notification.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        notification.is_read = True
        db.session.commit()
        # emit updated unread count to user's room so other sessions update their badge
        try:
            unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
            socketio.emit('unread_count', {'unread_count': unread}, room=f'user_{current_user.id}')
        except Exception:
            pass
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        try:
            socketio.emit('unread_count', {'unread_count': 0}, room=f'user_{current_user.id}')
        except Exception:
            pass
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/notifications')
@login_required
def notifications_page():
    """Render a full notifications page. Page fetches data from /api/notifications."""
    try:
        return render_template('notifications.html')
    except Exception:
        return render_template('notifications.html')


@app.route('/api/appointments/<int:appointment_id>/testimonial', methods=['POST'])
@login_required
def submit_testimonial(appointment_id):
    try:
        data = request.get_json() or {}
        rating = int(data.get('rating') or 0)
        content = data.get('content')
        is_public = data.get('is_public', True)

        apt = db.session.get(Appointment, appointment_id)
        if not apt:
            return jsonify({'error': 'appointment_not_found'}), 404

        # Ensure current_user is the patient for the appointment
        if current_user.role != 'patient' or getattr(current_user, 'id', None) != getattr(apt.patient, 'user_id', None):
            return jsonify({'error': 'unauthorized'}), 403

        t = Testimonial(patient_id=apt.patient_id, doctor_id=apt.doctor_id, appointment_id=apt.id, rating=rating, is_public=bool(is_public))
        t.content = content
        db.session.add(t)
        # store rating on appointment too
        try:
            apt.rating = rating
            apt.feedback = content
        except Exception:
            pass
        db.session.commit()
        return jsonify({'status': 'ok', 'testimonial_id': t.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'server_error', 'message': str(e)}), 500


# --------------------
# User call permissions API
# --------------------
@app.route('/api/user/permissions', methods=['GET'])
@login_required
def get_user_permissions():
    try:
        user = db.session.get(User, current_user.id)
        if not user:
            return jsonify({'error': 'user_not_found'}), 404

        return jsonify({
            'call_permissions_granted': bool(getattr(user, 'call_permissions_granted', False)),
            'call_permissions_granted_at': user.call_permissions_granted_at.isoformat() if getattr(user, 'call_permissions_granted_at', None) else None,
            'last_known_lat': getattr(user, 'last_known_lat', None),
            'last_known_lng': getattr(user, 'last_known_lng', None),
            'last_known_timezone': getattr(user, 'last_known_timezone', None)
        })
    except Exception as e:
        app.logger.exception('Failed to get user permissions')
        return jsonify({'error': 'server_error', 'message': str(e)}), 500


@app.route('/api/user/permissions', methods=['POST'])
@login_required
def update_user_permissions():
    try:
        data = request.get_json() or {}
        user = db.session.get(User, current_user.id)
        if not user:
            return jsonify({'error': 'user_not_found'}), 404

        granted = bool(data.get('call_permissions_granted', False))
        user.call_permissions_granted = granted
        if granted:
            user.call_permissions_granted_at = datetime.now(timezone.utc)

        lat = data.get('last_known_lat')
        lng = data.get('last_known_lng')
        tz = data.get('last_known_timezone')
        if lat is not None:
            try:
                user.last_known_lat = float(lat)
            except Exception:
                pass
        if lng is not None:
            try:
                user.last_known_lng = float(lng)
            except Exception:
                pass
        if tz:
            user.last_known_timezone = str(tz)

        db.session.add(user)
        db.session.commit()

        try:
            socketio.emit('user_permissions_updated', {'user_id': user.id, 'call_permissions_granted': user.call_permissions_granted}, room=f'user_{user.id}')
        except Exception:
            pass

        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to update user permissions')
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== HEALTH TIPS ENDPOINTS ====================

@app.route('/api/health-tips/patient/<int:patient_id>', methods=['GET'])
@login_required
def get_patient_health_tips(patient_id):
    """Get all health tips for a patient (accessible by doctor and patient)"""
    try:
        patient = db.session.get(Patient, patient_id)
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Check authorization: patient can view own tips, doctor can view tips for their patients
        if current_user.id != patient.user_id and current_user.role == 'patient':
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            if not doctor:
                return jsonify({'error': 'Doctor profile not found'}), 403
        
        # Get all health tips for this patient
        health_tips = HealthTip.query.filter_by(patient_id=patient_id).order_by(
            HealthTip.created_at.desc()
        ).all()
        
        tips_data = []
        for tip in health_tips:
            tips_data.append({
                'id': tip.id,
                'title': tip.title,
                'description': tip.description,
                'doctor_id': tip.doctor_id,
                'doctor_name': tip.doctor.user.first_name + ' ' + tip.doctor.user.last_name,
                'appointment_id': tip.appointment_id,
                'created_at': tip.created_at.isoformat(),
                'updated_at': tip.updated_at.isoformat()
            })
        
        return jsonify({'health_tips': tips_data, 'total': len(tips_data)})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    # NOTE: duplicate appointment-specific testimonial route removed (kept canonical /api/appointments/<id>/testimonial earlier)


@app.route('/api/health-tips', methods=['POST'])
@login_required
def create_health_tip():
    """Create a new health tip (doctor only)"""
    try:
        if current_user.role != 'doctor':
            return jsonify({'error': 'Only doctors can create health tips'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required_fields = ['patient_id', 'title', 'description']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor:
            return jsonify({'error': 'Doctor profile not found'}), 404
        
        patient = db.session.get(Patient, data['patient_id'])
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Create new health tip
        health_tip = HealthTip(
            doctor_id=doctor.id,
            patient_id=patient.id,
            appointment_id=data.get('appointment_id'),
            title=data['title'],
            description=data['description']
        )
        
        db.session.add(health_tip)
        db.session.commit()
        
        # Emit real-time notification to patient (emit to personal room)
        patient_user = db.session.get(User, patient.user_id)
        if patient_user:
            # Use the Socket.IO server instance to emit from a Flask route (request context has no namespace)
            socketio.emit('new_health_tip', {
                'tip_id': health_tip.id,
                'title': health_tip.title,
                'doctor_name': current_user.first_name + ' ' + current_user.last_name
            }, room=f'user_{patient_user.id}')
        
        return jsonify({
            'success': True,
            'health_tip_id': health_tip.id,
            'message': 'Health tip created successfully'
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/health-tips/<int:tip_id>', methods=['PUT'])
@login_required
def update_health_tip(tip_id):
    """Update a health tip (doctor only)"""
    try:
        if current_user.role != 'doctor':
            return jsonify({'error': 'Only doctors can update health tips'}), 403
        
        health_tip = db.session.get(HealthTip, tip_id)
        if not health_tip:
            return jsonify({'error': 'Health tip not found'}), 404
        
        # Check authorization: only creator doctor can update
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if health_tip.doctor_id != doctor.id:
            return jsonify({'error': 'You can only edit your own health tips'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields
        if 'title' in data:
            health_tip.title = data['title']
        if 'description' in data:
            health_tip.description = data['description']
        
        health_tip.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        # Emit real-time notification to patient
        patient = db.session.get(Patient, health_tip.patient_id)
        patient_user = db.session.get(User, patient.user_id)
        if patient_user:
            # Emit from Flask route using socketio server instance
            socketio.emit('health_tip_updated', {
                'tip_id': health_tip.id,
                'title': health_tip.title,
                'doctor_name': current_user.first_name + ' ' + current_user.last_name
            }, room=f'user_{patient_user.id}')
        
        return jsonify({'success': True, 'message': 'Health tip updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/health-tips/<int:tip_id>', methods=['DELETE'])
@login_required
def delete_health_tip(tip_id):
    """Delete a health tip (doctor only)"""
    try:
        if current_user.role != 'doctor':
            return jsonify({'error': 'Only doctors can delete health tips'}), 403
        
        health_tip = db.session.get(HealthTip, tip_id)
        if not health_tip:
            return jsonify({'error': 'Health tip not found'}), 404
        
        # Check authorization: only creator doctor can delete
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if health_tip.doctor_id != doctor.id:
            return jsonify({'error': 'You can only delete your own health tips'}), 403
        
        patient_id = health_tip.patient_id
        db.session.delete(health_tip)
        db.session.commit()
        
        # Emit real-time notification to patient
        patient = db.session.get(Patient, patient_id)
        patient_user = db.session.get(User, patient.user_id)
        if patient_user:
            # Emit from Flask route using socketio server instance
            socketio.emit('health_tip_deleted', {
                'tip_id': tip_id,
                'doctor_name': current_user.first_name + ' ' + current_user.last_name
            }, room=f'user_{patient_user.id}')
        
        return jsonify({'success': True, 'message': 'Health tip deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@socketio.on('health_tip_viewed')
def handle_health_tip_viewed(data):
    """Handle when patient views a health tip"""
    try:
        tip_id = data.get('tip_id')
        health_tip = db.session.get(HealthTip, tip_id)
        
        if health_tip:
            patient = db.session.get(Patient, health_tip.patient_id)
            if patient.user_id == current_user.id:
                # Emit to doctor that patient viewed the tip
                doctor_user = db.session.get(User, health_tip.doctor.user_id)
                if doctor_user:
                    emit('patient_viewed_health_tip', {
                        'tip_id': tip_id,
                        'patient_name': current_user.first_name + ' ' + current_user.last_name
                    }, room=f'user_{doctor_user.id}')
    except Exception as e:
        print(f"Error handling health tip viewed: {e}")


if __name__ == '__main__':
    cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
    cleanup_thread.start()
    
    port = int(os.environ.get('PORT', 5000))
    
    # Use the detected async backend name in the startup message
    async_backend = getattr(socketio.server, 'async_mode', None) or 'async'
    print(f"🚀 Starting application on port {port} with async backend={async_backend}")

    try:
        use_reloader = False
        if SOCKETIO_AVAILABLE:
            socketio.run(
                app,
                host='0.0.0.0',
                port=port,
                debug=debug_mode,
                log_output=debug_mode,
                allow_unsafe_werkzeug=debug_mode,
                use_reloader=use_reloader
            )
        else:
            from gevent.pywsgi import WSGIServer
            http_server = WSGIServer(('0.0.0.0', port), app)
            print(f"Server starting on port {port}")
            http_server.serve_forever()
    except TypeError:

        if SOCKETIO_AVAILABLE:
            socketio.run(
                app,
                host='0.0.0.0',
                port=port,
                debug=debug_mode,
                log_output=debug_mode,
                allow_unsafe_werkzeug=debug_mode
            )
    else:
        from gevent.pywsgi import WSGIServer
        http_server = WSGIServer(('0.0.0.0', port), app)
        print(f"Server starting on port {port}")
        http_server.serve_forever()