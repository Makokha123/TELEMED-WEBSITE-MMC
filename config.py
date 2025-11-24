import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = 'csrf-secret-key-change-in-production'
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # File Upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    
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
    STRICT_PROFILE_VALIDATION = False
    