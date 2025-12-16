import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    # Database - Use Neon PostgreSQL
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 
        'postgresql://neondb_owner:npg_tBcr3dVmolJ6@ep-square-scene-aesfpdul4-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True
    }
    
    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = 'csrf-secret-key-change-in-production'
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # File Upload
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_SIZE', 5 * 1024 * 1024))
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'static/uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'wav', 'mp3', 'mp4'}
    
    # Mail settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Social Authentication
    GOOGLE_OAUTH_CLIENT_ID = os.environ.get('GOOGLE_OAUTH_CLIENT_ID') or 'your-google-client-id'
    GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET') or 'your-google-client-secret'
    
    FACEBOOK_OAUTH_CLIENT_ID = os.environ.get('FACEBOOK_OAUTH_CLIENT_ID') or 'your-facebook-app-id'
    FACEBOOK_OAUTH_CLIENT_SECRET = os.environ.get('FACEBOOK_OAUTH_CLIENT_SECRET') or 'your-facebook-app-secret'
    # Application feature flags
    PROFILE_REDIRECT_REQUIRE_DOB_ONLY = False
    STRICT_PROFILE_VALIDATION = os.environ.get('STRICT_PROFILE_VALIDATION', 'False').lower() == 'true'
