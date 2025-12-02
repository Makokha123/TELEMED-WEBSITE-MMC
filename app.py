
import gc
from flask import Flask
from datetime import datetime, timedelta

import urllib
from models import Communication, PatientVital, Payment, Report

# Jinja2 filter for timeago
def timeago(dt):
    if not dt:
        return "N/A"
    now = datetime.utcnow()
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


from flask import Flask
from authlib.integrations.flask_client import OAuth
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook

app = Flask(__name__)

# Attempt to import Flask-SocketIO; provide graceful fallbacks if unavailable.
# Update your Socket.IO initialization
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
    SOCKETIO_AVAILABLE = True
    
    # Configure Socket.IO for Render
    socketio = SocketIO(
        app, 
        cors_allowed_origins="*",
        async_mode='eventlet',
        logger=True,
        engineio_logger=True,
        ping_timeout=60,  # Increase ping timeout
        ping_interval=25,  # Increase ping interval
        max_http_buffer_size=1e8  # 100MB limit
    )
    print("✓ Socket.IO initialized with eventlet")
except ImportError as e:
    print(f"⚠ Socket.IO not available: {e}")
    SOCKETIO_AVAILABLE = False
    socketio = None


    def emit(*args, **kwargs):
        """No-op emit fallback when Flask-SocketIO isn't installed."""
        return None

    def join_room(*args, **kwargs):
        """No-op join_room fallback when Flask-SocketIO isn't installed."""
        return None

    def leave_room(*args, **kwargs):
        """No-op leave_room fallback when Flask-SocketIO isn't installed."""
        return None

    def disconnect(*args, **kwargs):
        """No-op disconnect fallback when Flask-SocketIO isn't installed."""
        return None

# Twitter OAuth integration removed — disable related variables
make_twitter_blueprint = None
twitter = None
HAVE_TWITTER_DANCE = False
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import aliased
from flask import Flask, g, render_template, request, jsonify, redirect, url_for, flash, session
from sqlalchemy.orm import joinedload
from sqlalchemy import func, distinct
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.utils import secure_filename
from uuid import uuid4
from io import BytesIO
from flask import send_file, abort
from PIL import Image
# Load environment from .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Import models (after attempting to load .env so ENCRYPTION_KEY can be read)
from models import SocialAccount, db, User, Patient, Doctor, Appointment, AuditLog, Testimonial, MedicalRecord, _hash_value, encrypt_file_bytes, decrypt_file_bytes
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import secrets
import string
from config import Config
import os

# Initialize serializer for password reset tokens
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production-12345'))
from datetime import datetime
from datetime import datetime, timedelta, date
import json
import hmac
import hashlib
from flask_migrate import Migrate
import psutil

try:
    from config import Config
except ImportError:
    class Config:
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'mp3', 'wav', 'mp4'}
        MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB

app = Flask(__name__)

# Global dictionary to track online users for Socket.IO presence
user_sockets = {}
user_last_seen = {}
active_calls = {}

def configure_app():
    """Configure Flask application with environment variables"""
    # Security
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production-12345')
    app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_UPLOAD_SIZE', 5 * 1024 * 1024))
    
    # Database configuration with URL decoding
    database_url = os.getenv("DATABASE_URL") or 'sqlite:///clinic.db'
    
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
        'pool_size': 20,
        'max_overflow': 30
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
    
    # Logging
    app.config['LOG_LEVEL'] = os.getenv('LOG_LEVEL', 'INFO')

configure_app()

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
oauth = OAuth(app)

# Initialize Socket.IO with eventlet for best performance
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
    SOCKETIO_AVAILABLE = True
    socketio = SocketIO(
        app, 
        cors_allowed_origins="*",
        async_mode='eventlet',  # Use eventlet for WebSocket support
        logger=True,
        engineio_logger=True
    )
    print("✓ Socket.IO initialized with eventlet")
except ImportError as e:
    print(f"⚠ Socket.IO not available: {e}")
    SOCKETIO_AVAILABLE = False
    socketio = None

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
            
            # Create default users
            create_default_users()
            
            # Create uploads directory
            uploads_dir = app.config['UPLOAD_FOLDER']
            if not os.path.exists(uploads_dir):
                os.makedirs(uploads_dir, exist_ok=True)
                print(f"✓ Created uploads directory: {uploads_dir}")
                
        except Exception as e:
            print(f"✗ Database initialization error: {e}")
            import traceback
            traceback.print_exc()

# Run database initialization
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
    storage=SQLAlchemyStorage(SocialAccount, db.session, user=current_user)
)

facebook_bp = make_facebook_blueprint(
    client_id=app.config['FACEBOOK_OAUTH_CLIENT_ID'],
    client_secret=app.config['FACEBOOK_OAUTH_CLIENT_SECRET'],
    scope=["email", "public_profile"],
    storage=SQLAlchemyStorage(SocialAccount, db.session, user=current_user)
)

twitter_bp = None

# Register available OAuth blueprints
app.register_blueprint(google_bp, url_prefix="/login")
app.register_blueprint(facebook_bp, url_prefix="/login")

def cleanup_old_sessions():
    """Clean up old user sessions"""
    cutoff_time = datetime.utcnow() - timedelta(hours=1)
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
        threading.Event().wait(3600)  # Wait 1 hour
        cleanup_old_sessions()

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
            filename = secure_filename(profile_picture.filename)
            if allowed_file(filename):
                storage_name = f"{uuid4().hex}__{filename}.enc"
                username_for = safe_username(current_user)
                rel_root = _uploads_rel_root() or 'uploads'
                rel_dir = os.path.join(rel_root, username_for, 'profile_pictures').replace('\\', '/')
                full_dir = os.path.join(app.root_path, rel_dir)
                os.makedirs(full_dir, exist_ok=True)
                full_path = os.path.join(full_dir, storage_name)
                rel_path_for_db = os.path.join(rel_dir, storage_name).replace('\\', '/')

                raw = profile_picture.read()
                try:
                    encrypted_bytes = encrypt_file_bytes(raw)
                    with open(full_path, 'wb') as fh:
                        fh.write(encrypted_bytes)
                    current_user.profile_picture = rel_path_for_db
                except Exception as e:
                    flash('Error saving profile picture: ' + str(e), 'error')
            else:
                flash('Invalid profile picture file type.', 'error')
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
                    today = datetime.utcnow().date()
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
        
        patient = current_user.patient_profile
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
    
    # Get categorized appointments - fix the data structure
    try:
        appointments_response = get_patient_appointments_categorized()
        if isinstance(appointments_response, tuple):
            appointments_data = appointments_response[0].get_json()
        else:
            appointments_data = appointments_response.get_json()
    except Exception as e:
        print(f"Error getting appointments: {e}")
        appointments_data = {
            'upcoming': [],
            'pending_confirmation': [],
            'completed': [],
            'rescheduled': []
        }

    # Convert appointment dates from strings to datetime objects for the template
    def process_appointments(appointments_list):
        processed = []
        for appointment in appointments_list:
            # Create a copy of the appointment dictionary
            processed_appointment = appointment.copy()
            
            # Convert appointment_date string to datetime object if it exists
            if appointment.get('appointment_date'):
                try:
                    if isinstance(appointment['appointment_date'], str):
                        processed_appointment['appointment_date'] = datetime.fromisoformat(appointment['appointment_date'].replace('Z', '+00:00'))
                except (ValueError, AttributeError) as e:
                    print(f"Error parsing date {appointment['appointment_date']}: {e}")
                    # Keep as string if parsing fails
                    processed_appointment['appointment_date'] = appointment['appointment_date']
            
            # Convert created_at string to datetime object if it exists
            if appointment.get('created_at'):
                try:
                    if isinstance(appointment['created_at'], str):
                        processed_appointment['created_at'] = datetime.fromisoformat(appointment['created_at'].replace('Z', '+00:00'))
                except (ValueError, AttributeError) as e:
                    print(f"Error parsing created_at {appointment['created_at']}: {e}")
                    # Keep as string if parsing fails
                    processed_appointment['created_at'] = appointment['created_at']
            
            processed.append(processed_appointment)
        return processed

    # Process all appointment categories
    upcoming_processed = process_appointments(appointments_data.get('upcoming', []))
    pending_confirmation_processed = process_appointments(appointments_data.get('pending_confirmation', []))
    completed_processed = process_appointments(appointments_data.get('completed', []))
    rescheduled_processed = process_appointments(appointments_data.get('rescheduled', []))

    return render_template('patient/appointment.html', 
                         user=current_user, 
                         patient=patient,
                         doctors=doctors,
                         upcoming=upcoming_processed,
                         pending_confirmation=pending_confirmation_processed,
                         completed=completed_processed,
                         rescheduled=rescheduled_processed)

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
                today = datetime.utcnow().date()
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

    # Load doctor profile
    doctor = current_user.doctor_profile
    if not doctor:
        try:
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        except Exception:
            doctor = None

    # Upcoming appointments for this doctor
    try:
        appointments = Appointment.query.filter_by(doctor_id=doctor.id if doctor else None).order_by(Appointment.appointment_date).all()
    except Exception:
        appointments = []

    # Patients seen this week
    from datetime import datetime, timedelta, timezone
    now_utc = datetime.now(timezone.utc)
    start_week = now_utc - timedelta(days=now_utc.weekday())
    if doctor:
        # Use subquery to count unique patients for non-PostgreSQL backends
        from sqlalchemy import func
        patients_this_week = db.session.query(func.count(func.distinct(Appointment.patient_id))).filter(
            Appointment.doctor_id == doctor.id,
            Appointment.appointment_date >= start_week
        ).scalar()
    else:
        patients_this_week = 0

    # Pending prescriptions (appointments with status 'scheduled' and not completed)
    pending_prescriptions = Appointment.query.filter_by(doctor_id=doctor.id, status='scheduled').count() if doctor else 0

    # Urgent cases (appointments with status 'urgent')
    urgent_cases = Appointment.query.filter_by(doctor_id=doctor.id, status='urgent').count() if doctor else 0

    # Helper to format last visit as 'time ago' string
    def format_timeago(dt):
        if not dt:
            return "N/A"
        now = datetime.utcnow()
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
    if doctor:
        from sqlalchemy import desc
        appts = Appointment.query.filter_by(doctor_id=doctor.id).order_by(desc(Appointment.appointment_date)).all()
        seen = set()
        for appt in appts:
            pid = appt.patient_id
            if pid not in seen:
                patient = db.session.get(Patient, pid)
                if patient:
                    recent_patients.append({
                        'user': patient.user,
                        'last_visit': format_timeago(appt.appointment_date)
                    })
                    seen.add(pid)
            if len(recent_patients) >= 6:
                break

    return render_template(
        'doctor/doctor_dashboard.html',
        doctor=doctor,
        appointments=appointments,
        patients_this_week=patients_this_week,
        pending_prescriptions=pending_prescriptions,
        urgent_cases=urgent_cases,
        recent_patients=recent_patients
    )
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
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
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
                         now=datetime.utcnow())


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
        encrypted = encrypt_file_bytes(data)

        comm = Communication(
            appointment_id=appointment.id,
            sender_id=current_user.id,
            message_type=message_type,
            encrypted_file_blob=encrypted
        )
        db.session.add(comm)
        db.session.commit()
        return jsonify({'status': 'ok', 'comm_id': comm.id}), 201
    except Exception as e:
        db.session.rollback()
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

        if not appointment_id or not message_type or not blob_b64:
            emit('save_recording_response', {'error': 'missing parameters'})
            return

        try:
            raw = base64.b64decode(blob_b64)
            encrypted = encrypt_file_bytes(raw)
            comm = Communication(
                appointment_id=appointment_id,
                sender_id=sender_id or current_user.id,
                message_type=message_type,
                encrypted_file_blob=encrypted
            )
            db.session.add(comm)
            db.session.commit()
            emit('save_recording_response', {'status': 'ok', 'comm_id': comm.id})
        except Exception as e:
            db.session.rollback()
            emit('save_recording_response', {'error': str(e)})

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

    # Load all messages for this appointment
    messages = Communication.query.filter_by(
        appointment_id=appointment_id
    ).order_by(Communication.timestamp).all()

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

# Add this route for appointment details
@app.route('/api/appointment/<int:appointment_id>/details')
@login_required
def get_appointment_details(appointment_id):
    """Get appointment details for confirmation"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'error': 'Access denied'}), 403
    
    doctor = Doctor.query.get(appointment.doctor_id)
    doctor_user = User.query.get(doctor.user_id) if doctor else None
    
    return jsonify({
        'id': appointment.id,
        'doctor_first_name': doctor_user.first_name if doctor_user else '',
        'doctor_last_name': doctor_user.last_name if doctor_user else '',
        'doctor_specialization': doctor.specialization if doctor else '',
        'appointment_date': appointment.appointment_date.isoformat(),
        'consultation_type': appointment.consultation_type,
        'symptoms': appointment.symptoms,
        'status': appointment.status
    })

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
        appointment = Appointment.query.get(payment.appointment_id)
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
        doctor = Doctor.query.get(appointment.doctor_id)
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
        doctor = Doctor.query.get(data.get('doctor_id'))
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

        if not appointment_id or not message_type or not blob_b64:
            emit('save_recording_response', {'error': 'missing parameters'})
            return

        try:
            raw = base64.b64decode(blob_b64)
            encrypted = encrypt_file_bytes(raw)
            comm = Communication(
                appointment_id=appointment_id,
                sender_id=sender_id or current_user.id,
                message_type=message_type,
                encrypted_file_blob=encrypted
            )
            db.session.add(comm)
            db.session.commit()
            emit('save_recording_response', {'status': 'ok', 'comm_id': comm.id})
        except Exception as e:
            db.session.rollback()
            emit('save_recording_response', {'error': str(e)})


# Profile picture upload (users can upload their own; admin may upload for others)
@app.route('/upload_profile_picture', methods=['POST'])
@login_required
@csrf.exempt
def upload_profile_picture():
    # Accept multipart/form-data with key 'file' and optional 'user_id' for admin
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
            try:
                target_user = db.session.get(User, uid) or target_user
            except Exception:
                target_user = User.query.get(uid) or target_user
        except Exception:
            pass

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        storage_name = f"{uuid4().hex}__{filename}.enc"

        # Construct per-user uploads folder: static/uploads/<username>/profile_pictures/
        username_for = safe_username(target_user)
        rel_root = _uploads_rel_root() or 'uploads'
        rel_dir = os.path.join(rel_root, username_for, 'profile_pictures').replace('\\', '/')
        full_dir = os.path.join(app.root_path, rel_dir)
        os.makedirs(full_dir, exist_ok=True)

        full_path = os.path.join(full_dir, storage_name)
        rel_path_for_db = os.path.join(rel_dir, storage_name).replace('\\', '/')

        raw = file.read()
        try:
            encrypted_bytes = encrypt_file_bytes(raw)
        except Exception as e:
            return jsonify({'success': False, 'error': 'Encryption failed', 'detail': str(e)}), 500

        with open(full_path, 'wb') as fh:
            fh.write(encrypted_bytes)

        # Save stored relative path on user record (relative to static)
        target_user.profile_picture = rel_path_for_db
        db.session.add(target_user)
        db.session.commit()

        return jsonify({'success': True, 'file_path': rel_path_for_db, 'user_id': target_user.id}), 201

    return jsonify({'success': False, 'error': 'Invalid file type'}), 400


# Serve decrypted profile picture for a user
@app.route('/profile_picture/<int:user_id>')
def profile_picture(user_id):
    user = User.query.get_or_404(user_id)
    stored_path = user.profile_picture
    if not stored_path:
        return ('', 404)

    # If profile_picture is an external URL (from OAuth), redirect to it
    if isinstance(stored_path, str) and stored_path.startswith('http'):
        return redirect(stored_path)

    # Resolve stored path relative to application root if necessary
    full_path = resolve_stored_path(stored_path)
    if not full_path or not os.path.exists(full_path):
        # try as relative under UPLOAD_FOLDER
        alt = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), os.path.basename(stored_path))
        if os.path.exists(alt):
            full_path = alt

    if not full_path or not os.path.exists(full_path):
        return ('', 404)

    try:
        with open(full_path, 'rb') as fh:
            encrypted = fh.read()
        decrypted = decrypt_file_bytes(encrypted)
    except Exception:
        return ('', 500)

    # Guess mimetype from original filename
    orig_name = os.path.basename(stored_path)
    if '__' in orig_name:
        orig_part = orig_name.split('__', 1)[1]
        if orig_part.endswith('.enc'):
            orig_name = orig_part[:-4]

    # simple mimetype mapping
    ext = os.path.splitext(orig_name)[1].lower()
    mime = 'application/octet-stream'
    if ext in ('.jpg', '.jpeg'):
        mime = 'image/jpeg'
    elif ext == '.png':
        mime = 'image/png'
    elif ext == '.gif':
        mime = 'image/gif'

    bio = BytesIO(decrypted)
    bio.seek(0)
    try:
        return send_file(bio, mimetype=mime)
    except TypeError:
        return send_file(bio, attachment_filename=orig_name, mimetype=mime)

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
                         })

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
        timestamp=datetime.utcnow()
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
                         doctor=doctor)

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
                         patient=patient)

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
def submit_testimonial():
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


@app.route('/api/testimonials')
def get_testimonials():
    """Return recent public testimonials for display."""
    try:
        limit = int(request.args.get('limit', 10))
    except Exception:
        limit = 10

    testimonials = Testimonial.query.filter_by(is_public=True).order_by(Testimonial.created_at.desc()).limit(limit).all()
    out = []
    for t in testimonials:
        # resolve patient and doctor display names safely
        try:
            patient_name = t.patient.user.get_display_name() if t.patient and t.patient.user else None
        except Exception:
            patient_name = None
        try:
            doctor_user = t.doctor.user if t.doctor and getattr(t.doctor, 'user', None) else None
            doctor_name = doctor_user.get_display_name() if doctor_user else None
            doctor_avg = t.doctor.average_rating if t.doctor else None
        except Exception:
            doctor_name = None
            doctor_avg = None

        out.append({
            'id': t.id,
            'patient_name': patient_name,
            'doctor_name': doctor_name,
            'doctor_id': t.doctor_id,
            'rating': t.rating,
            'content': t.content,
            'created_at': t.created_at.isoformat(),
            'doctor_average': doctor_avg
        })

    return jsonify({'testimonials': out})

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
@app.route('/api/upload_file', methods=['POST'])
@login_required
@csrf.exempt
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Store encrypted file with a unique prefix and .enc extension
        storage_name = f"{uuid4().hex}__{filename}.enc"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)

        # Read raw file bytes and encrypt before saving
        raw = file.read()
        try:
            encrypted_bytes = encrypt_file_bytes(raw)
        except Exception as e:
            return jsonify({'error': 'Failed to encrypt file', 'detail': str(e)}), 500

        # Ensure upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        with open(file_path, 'wb') as fh:
            fh.write(encrypted_bytes)

        return jsonify({
            'success': True,
            'file_path': file_path,
            'filename': filename
        })
    
    return jsonify({'error': 'Invalid file type'}), 400

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
        # doctors may have created records; allow if they created it or admin/assigned
        if record.created_by != current_user.id:
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
    """Get doctor's appointments with patient info and payment status"""
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
    ).order_by(Appointment.appointment_date.desc()).all()
    
    appointments_data = []
    for appointment, patient, user, payment in appointments:
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
        
        appointments_data.append({
            'appointment_id': appointment.id,
            'patient_id': patient.id,
            'patient': {
                'id': patient.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email
            },
            'appointment_date': appointment.appointment_date.isoformat(),
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
        })
    
    return jsonify(appointments_data)

@app.route('/api/patient/appointments')
@login_required
def get_patient_appointments():
    """Get patient's appointments with doctor info and payment status"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    # Get appointments with doctor info and payment status
    appointments = db.session.query(
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
    
    appointments_data = []
    for appointment, doctor, user, payment in appointments:
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
        
        appointments_data.append({
            'appointment_id': appointment.id,
            'doctor_id': doctor.id,
            'doctor': {
                'id': doctor.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'specialization': doctor.specialization,
                'is_online': user.id in user_sockets
            },
            'appointment_date': appointment.appointment_date.isoformat(),
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
        })
    
    return jsonify(appointments_data)

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

@app.route('/api/patient/appointments/categorized')
@login_required
def get_patient_appointments_categorized():
    """Get patient's appointments categorized by status"""
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
    ).order_by(Appointment.appointment_date.desc()).all()
    
    # Categorize appointments
    upcoming = []
    pending_confirmation = []
    completed = []
    rescheduled = []
    
    for appointment, doctor, user, payment in appointments_data:
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
            'appointment_date': appointment_date.isoformat() if appointment_date else None,
            'consultation_type': appointment.consultation_type,
            'symptoms': appointment.symptoms,
            'notes': appointment.notes,
            'status': appointment.status,
            'payment_status': payment_status,
            'rating': appointment.rating if hasattr(appointment, 'rating') else None,
            'created_at': created_at.isoformat() if created_at else None
        }
        
        # Categorize based on status and date
        now = datetime.utcnow()
        
        if appointment.status == 'completed':
            completed.append(appointment_data)
        elif appointment.status == 'rescheduled':
            rescheduled.append(appointment_data)
        elif appointment.status == 'pending':
            pending_confirmation.append(appointment_data)
        elif appointment.status in ['confirmed', 'scheduled']:
            if appointment_date and appointment_date > now:
                upcoming.append(appointment_data)
            else:
                # Past confirmed appointments that aren't completed
                completed.append(appointment_data)
        elif appointment.status == 'cancelled':
            # Skip cancelled appointments for these categories
            pass
    
    return jsonify({
        'upcoming': upcoming,
        'pending_confirmation': pending_confirmation,
        'completed': completed,
        'rescheduled': rescheduled
    })


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
@app.route('/doctor/patients', methods=['GET'])
def get_doctor_patients():
    """Render all patients for a doctor in HTML"""
    patients = db.session.query(Patient, User, Appointment).join(
        User, Patient.user_id == User.id
    ).join(
        Appointment, Appointment.patient_id == Patient.id
    ).filter(
        Appointment.doctor_id == current_user.id
    ).distinct(Patient.id).all()

    # Prepare a list of patient dicts for the template
    patient_list = []
    for patient, user, appointment in patients:
        patient_list.append({
            'id': patient.id,
            'user_id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'phone': user.phone,
            'last_message': getattr(appointment, 'last_message', ''),
            'last_message_time': getattr(appointment, 'last_message_time', ''),
            'unread_count': getattr(appointment, 'unread_count', 0)
        })

    return render_template('doctor/patients.html', patients=patient_list)

# API to get messages for appointment (patient/doctor communication)
@app.route('/api/appointment/<int:appointment_id>/messages', methods=['GET'])
@login_required
def get_appointment_messages(appointment_id):
    """Get all messages for an appointment"""
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
            try:
                sender_name = safe_display_name(msg.sender)
            except Exception:
                sender_name = getattr(msg.sender, 'first_name', '') + ' ' + getattr(msg.sender, 'last_name', '')
            
            messages_data.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'sender_name': sender_name,
                'message_type': msg.message_type or 'text',
                'content': msg.content or '',
                'file_path': msg.file_path,
                'timestamp': msg.timestamp.isoformat() if msg.timestamp else None,
                'is_sent': msg.sender_id == current_user.id,
                'is_read': msg.is_read if hasattr(msg, 'is_read') else True,
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
    
    filename = secure_filename(f"voice_{current_user.id}_{datetime.utcnow().timestamp()}.wav")
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    audio_file.save(file_path)
    
    communication = Communication(
        appointment_id=appointment_id,
        sender_id=current_user.id,
        message_type='voice_note',
        content='[Voice Note]',
        file_path=file_path
    )
    
    db.session.add(communication)
    db.session.commit()
    
    return jsonify({'success': True, 'message_id': communication.id})

# API for doctor communication

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
@app.route('/api/patient/doctors', methods=['GET'])
@login_required
def get_patient_doctors():
    """Get all doctors patient has appointments with"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    # Get unique doctors who have appointments with this patient
    doctors = db.session.query(Doctor, User, Appointment).join(
        Appointment, Doctor.id == Appointment.doctor_id
    ).join(
        User, Doctor.user_id == User.id
    ).filter(Appointment.patient_id == patient.id).distinct(Doctor.id).order_by(
        Appointment.appointment_date.desc()
    ).all()
    
    doctors_data = []
    seen = set()
    for doctor, user, appointment in doctors:
        if doctor.id not in seen:
            seen.add(doctor.id)
            # Get last message
            last_message = Communication.query.filter_by(
                appointment_id=appointment.id
            ).order_by(Communication.timestamp.desc()).first()
            
            doctors_data.append({
                'id': doctor.id,
                'user_id': user.id,
                'first_name': getattr(user, 'first_name', ''),
                'last_name': getattr(user, 'last_name', ''),
                'phone': user.phone,
                'email': user.email,
                'specialization': doctor.specialization,
                'is_online': user.id in user_sockets,
                'last_seen': user_last_seen.get(user.id),
                'last_message': last_message.content if last_message else None,
                'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
                'unread_count': Communication.query.join(
                    Appointment, Communication.appointment_id == Appointment.id
                ).filter(
                    Appointment.patient_id == patient.id,
                    Appointment.doctor_id == doctor.id,
                    Communication.is_read == False,
                    Communication.sender_id != current_user.id
                ).count()
            })
    
    return jsonify(doctors_data)

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

# ============================================
# SOCKET.IO EVENT HANDLERS - REAL-TIME COMMUNICATION
# ============================================

@socketio.on_error_default
def default_error_handler(e):
    """Handle Socket.IO errors"""
    print(f'Socket.IO error: {e}')
    import traceback
    traceback.print_exc()

@socketio.on('connect')
def handle_connect():
    """Handle user connection with better error handling"""
    try:
        if not current_user.is_authenticated:
            print("Unauthenticated connection attempt")
            return False
        
        user_sockets[current_user.id] = request.sid
        user_last_seen[current_user.id] = datetime.utcnow().isoformat()
        
        emit('connection_response', {'data': 'Connected to server'})
        print(f'User {current_user.id} connected: {request.sid}')
        
    except Exception as e:
        print(f'Error in handle_connect: {e}')
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Handle user disconnection with cleanup"""
    try:
        if current_user.is_authenticated:
            user_id = current_user.id
            if user_id in user_sockets:
                del user_sockets[user_id]
            
            # Update last seen
            user_last_seen[user_id] = datetime.utcnow().isoformat()
            
            # Clean up active calls
            for apt_id, users in list(active_calls.items()):
                if user_id in users:
                    del users[user_id]
                    if not users:
                        del active_calls[apt_id]
            
            print(f'User {user_id} disconnected')
            
    except Exception as e:
        print(f'Error in handle_disconnect: {e}')

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# ============================================
# MESSAGING EVENTS
# ============================================

@socketio.on('send_message')
def handle_send_message(data):
    """Handle real-time message sending and update conversation"""
    if not current_user.is_authenticated:
        return {'success': False, 'error': 'Not authenticated'}

    try:
        appointment_id = data.get('appointment_id')
        doctor_id = data.get('doctor_id')
        content = data.get('content')

        # If client passed doctor_id (legacy), find latest appointment
        if not appointment_id and doctor_id:
            patient = Patient.query.filter_by(user_id=current_user.id).first()
            if not patient:
                return {'success': False, 'error': 'Patient profile not found'}
            appointment = Appointment.query.filter_by(
                doctor_id=doctor_id,
                patient_id=patient.id
            ).order_by(Appointment.appointment_date.desc()).first()
            if appointment:
                appointment_id = appointment.id

        if not appointment_id or not content:
            return {'success': False, 'error': 'Invalid data'}

        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return {'success': False, 'error': 'Appointment not found'}

        # Verify access
        if not verify_appointment_access(appointment, current_user):
            return {'success': False, 'error': 'Access denied'}

        # Save message to database
        communication = Communication(
            appointment_id=appointment_id,
            sender_id=current_user.id,
            message_type='text',
            content=content
        )
        db.session.add(communication)
        db.session.commit()

        message_data = {
            'id': communication.id,
            'sender_id': current_user.id,
            'sender_name': safe_display_name(current_user),
            'content': content,
            'timestamp': communication.timestamp.isoformat(),
            'appointment_id': appointment_id,
            'status': 'sent'
        }

        # Broadcast to both users in appointment
        appointment_room = f'appointment_{appointment_id}'
        emit('message_received', message_data, room=appointment_room)

        # Send the updated conversation back to the sender
        messages = Communication.query.filter_by(
            appointment_id=appointment_id
        ).order_by(Communication.timestamp).all()

        messages_data = []
        for msg in messages:
            messages_data.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'sender_name': msg.sender.first_name + ' ' + msg.sender.last_name,
                'message_type': msg.message_type,
                'content': msg.content,
                'timestamp': msg.timestamp.isoformat(),
                'is_read': msg.is_read
            })

        emit('conversation_updated', messages_data, room=appointment_room)

    except Exception as e:
        print(f'Error sending message: {str(e)}')
        emit('message_error', {'error': str(e)})


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
            msg = Communication.query.get(message_id)
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
        
        # Store call information
        call_info = {
            'appointment_id': appointment_id,
            'caller_id': current_user.id,
            'caller_name': caller_name,
            'caller_role': caller_role,
            'callee_id': callee_user_id,
            'call_type': 'video',
            'start_time': datetime.utcnow().isoformat(),
            'status': 'ringing'
        }
        
        active_calls[appointment_id] = call_info
        
        # Notify caller that call is ringing
        emit('call_ringing', {
            'appointment_id': appointment_id,
            'call_type': 'video'
        })
        
        # Prepare call notification data
        call_data = {
            'appointment_id': appointment_id,
            'caller_id': current_user.id,
            'caller_name': caller_name,
            'caller_role': caller_role,
            'callee_role': callee_role,
            'call_type': 'video',
            'appointment_date': appointment.appointment_date.isoformat(),
            'appointment_time': appointment.appointment_date.strftime('%H:%M'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Send incoming call notification to callee with ringtone
        callee_socket_id = user_sockets.get(callee_user_id)
        if callee_socket_id:
            emit('incoming_video_call', call_data, room=callee_socket_id)
        
        # Set call timeout (1 minute)
        def call_timeout():
            if appointment_id in active_calls and active_calls[appointment_id]['status'] == 'ringing':
                # Call timed out
                active_calls[appointment_id]['status'] = 'timeout'
                emit('call_timeout', {
                    'appointment_id': appointment_id,
                    'reason': 'No answer'
                })
                
                # Notify caller
                caller_socket_id = user_sockets.get(current_user.id)
                if caller_socket_id:
                    emit('call_ended', {
                        'appointment_id': appointment_id,
                        'reason': 'timeout',
                        'message': 'Call timed out - no answer'
                    }, room=caller_socket_id)
                
                # Create missed call notification for callee
                missed_call_data = {
                    'appointment_id': appointment_id,
                    'caller_name': caller_name,
                    'caller_role': caller_role,
                    'appointment_date': appointment.appointment_date.isoformat(),
                    'appointment_time': appointment.appointment_date.strftime('%H:%M'),
                    'timestamp': datetime.utcnow().isoformat(),
                    'type': 'missed_video_call'
                }
                
                if callee_socket_id:
                    emit('missed_call', missed_call_data, room=callee_socket_id)
                
                # Clean up
                if appointment_id in active_calls:
                    del active_calls[appointment_id]
        
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
        call_info['accepted_time'] = datetime.utcnow().isoformat()
        
        # Notify both parties that call is connected
        caller_socket_id = user_sockets.get(call_info['caller_id'])
        callee_socket_id = user_sockets.get(current_user.id)
        
        call_data = {
            'appointment_id': appointment_id,
            'caller_id': call_info['caller_id'],
            'callee_id': current_user.id,
            'call_type': 'video'
        }
        
        if caller_socket_id:
            emit('video_call_accepted', call_data, room=caller_socket_id)
        
        if callee_socket_id:
            emit('video_call_accepted', call_data, room=callee_socket_id)
        
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
        caller_socket_id = user_sockets.get(call_info['caller_id'])
        callee_id = call_info['callee_id']
        callee_socket_id = user_sockets.get(callee_id)
        
        end_data = {
            'appointment_id': appointment_id,
            'ended_by': current_user.id,
            'reason': data.get('reason', 'ended_by_user'),
            'message': data.get('message', 'Call ended')
        }
        
        if caller_socket_id:
            emit('video_call_ended', end_data, room=caller_socket_id)
        
        if callee_socket_id:
            emit('video_call_ended', end_data, room=callee_socket_id)
        
        # Clean up
        if appointment_id in active_calls:
            del active_calls[appointment_id]
        
        print(f'Video call ended for appointment {appointment_id}')
        
    except Exception as e:
        print(f'Error ending video call: {str(e)}')

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
        
        appointment_room = f'appointment_{appointment_id}'
        
        # Add to active calls
        if appointment_id not in active_calls:
            active_calls[appointment_id] = {}
        active_calls[appointment_id][current_user.id] = request.sid
        
        call_data = {
            'initiator_id': current_user.id,
            'initiator_name': safe_display_name(current_user),
            'appointment_id': appointment_id,
            'call_type': 'voice'
        }
        
        # Notify other participant
        emit('incoming_voice_call', call_data, room=appointment_room, skip_sid=request.sid)
        emit('call_initiated', call_data)
        
    except Exception as e:
        print(f'Error initiating voice call: {str(e)}')
        emit('call_error', {'error': str(e)})

@socketio.on('accept_voice_call')
def handle_accept_voice_call(data):
    """Accept an incoming voice call"""
    if not current_user.is_authenticated:
        return
    
    try:
        appointment_id = data.get('appointment_id')
        appointment_room = f'appointment_{appointment_id}'
        
        call_data = {
            'acceptor_id': current_user.id,
            'acceptor_name': safe_display_name(current_user),
            'appointment_id': appointment_id
        }
        
        emit('voice_call_accepted', call_data, room=appointment_room)
        
    except Exception as e:
        print(f'Error accepting voice call: {str(e)}')

@socketio.on('end_voice_call')
def handle_end_voice_call(data):
    """End a voice call"""
    if not current_user.is_authenticated:
        return
    
    try:
        appointment_id = data.get('appointment_id')
        appointment_room = f'appointment_{appointment_id}'
        
        # Remove from active calls
        if appointment_id in active_calls:
            if current_user.id in active_calls[appointment_id]:
                del active_calls[appointment_id][current_user.id]
            if not active_calls[appointment_id]:
                del active_calls[appointment_id]
        
        emit('voice_call_ended', {
            'ended_by': current_user.id,
            'appointment_id': appointment_id
        }, room=appointment_room)
        
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



if __name__ == '__main__':
    cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
    cleanup_thread.start()
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run application with Socket.IO if available
    if SOCKETIO_AVAILABLE:
        print(f"🚀 Starting application on port {port} with Socket.IO support")
        
        # For development
        if os.environ.get('ENVIRONMENT') == 'development':
            socketio.run(app, host='0.0.0.0', port=port, debug=True)
        else:
            # For production (Render)
            socketio.run(app, host='0.0.0.0', port=port, debug=False, 
                        log_output=True, allow_unsafe_werkzeug=True)
    else:
        print(f"🚀 Starting application on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)