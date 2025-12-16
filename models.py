from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import os
import hashlib
import logging
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import func

db = SQLAlchemy()

# Report model for real-time reports viewing
class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    doctor = db.relationship('Doctor', foreign_keys=[doctor_id])

# Prescription model for real-time prescription creation
class Prescription(db.Model):
    __tablename__ = 'prescriptions'

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=True)
    medication = db.Column(db.String(255), nullable=False)
    dosage = db.Column(db.String(255), nullable=False)
    instructions = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # Expiry and dispensing fields
    is_expired = db.Column(db.Boolean, default=False, nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=True)
    expired_by = db.Column(db.Integer, nullable=True)
    dispensed_by = db.Column(db.Integer, nullable=True)
    dispensed_at = db.Column(db.DateTime, nullable=True)

    doctor = db.relationship('Doctor', foreign_keys=[doctor_id])
    patient = db.relationship('Patient', foreign_keys=[patient_id])
    appointment = db.relationship('Appointment', foreign_keys=[appointment_id])
_ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not _ENCRYPTION_KEY:
    # WARNING: generating a key here will make existing encrypted data unreadable across restarts.
    logging.warning('ENCRYPTION_KEY not set in environment; generating ephemeral key (NOT for production).')
    _ENCRYPTION_KEY = Fernet.generate_key().decode()

# Ensure key is bytes
try:
    _FERNET = Fernet(_ENCRYPTION_KEY.encode())
except Exception as e:
    logging.error(f"Failed to initialize Fernet: {e}")
    _FERNET = None

def _encrypt_text(plaintext: str) -> bytes:
    if plaintext is None or _FERNET is None:
        return None
    try:
        return _FERNET.encrypt(plaintext.encode())
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        return None

def _decrypt_text(token: bytes) -> str:
    if token is None or _FERNET is None:
        return None
    try:
        return _FERNET.decrypt(token).decode()
    except InvalidToken:
        logging.error("Invalid token - encryption key may have changed")
        return "[Encryption Error]"
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return "[Decryption Error]"

def _hash_value(value: str) -> str:
    if value is None:
        return None
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()

# Binary file encryption helpers (encrypt/decrypt raw bytes)
def encrypt_file_bytes(data: bytes) -> bytes:
    if data is None or _FERNET is None:
        return None
    try:
        return _FERNET.encrypt(data)
    except Exception as e:
        logging.error(f"File encryption failed: {e}")
        return None

def decrypt_file_bytes(token: bytes) -> bytes:
    if token is None or _FERNET is None:
        return None
    try:
        return _FERNET.decrypt(token)
    except Exception as e:
        logging.error(f"File decryption failed: {e}")
        return None

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Encrypted email and deterministic hash for lookups
    encrypted_email = db.Column(db.LargeBinary, nullable=False)
    email_hash = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'doctor', 'patient'
    encrypted_first_name = db.Column(db.LargeBinary, nullable=False)
    encrypted_last_name = db.Column(db.LargeBinary, nullable=False)
    encrypted_phone = db.Column(db.LargeBinary)
    encrypted_profile_picture_path = db.Column(db.String(512))  # Encrypted path stored as text
    # Binary profile picture storage (encrypted)
    profile_picture_blob = db.Column(db.LargeBinary)  # Encrypted image bytes
    profile_picture_mime = db.Column(db.String(50))   # Content type (e.g., 'image/jpeg')
    profile_picture_name = db.Column(db.String(255))  # Original filename for reference
    date_of_birth = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)

    allow_user_creation = db.Column(db.Boolean, default=False)
    show_availability = db.Column(db.Boolean, default=True)
    share_data = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    call_permissions_granted = db.Column(db.Boolean, default=False, nullable=False)
    call_permissions_granted_at = db.Column(db.DateTime, nullable=True)
    last_known_lat = db.Column(db.Float, nullable=True)
    last_known_lng = db.Column(db.Float, nullable=True)
    last_known_timezone = db.Column(db.String(64), nullable=True)

    # Relationships
    patient_profile = db.relationship('Patient', backref='user', uselist=False, foreign_keys='Patient.user_id')
    doctor_profile = db.relationship('Doctor', backref='user', uselist=False, foreign_keys='Doctor.user_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password with proper error handling"""
        try:
            return check_password_hash(self.password_hash, password)
        except Exception as e:
            logging.error(f"Password check error for user {self.username}: {e}")
            return False

    # email property (encrypted in DB) with deterministic hash for lookups
    @property
    def email(self):
        return _decrypt_text(self.encrypted_email) if self.encrypted_email else None

    @email.setter
    def email(self, value):
        if value is None:
            self.encrypted_email = None
            self.email_hash = None
        else:
            self.encrypted_email = _encrypt_text(value)
            self.email_hash = _hash_value(value)

    @property
    def first_name(self):
        return _decrypt_text(self.encrypted_first_name) if self.encrypted_first_name else None

    @first_name.setter
    def first_name(self, value):
        self.encrypted_first_name = _encrypt_text(value) if value is not None else None

    @property
    def last_name(self):
        return _decrypt_text(self.encrypted_last_name) if self.encrypted_last_name else None

    @last_name.setter
    def last_name(self, value):
        self.encrypted_last_name = _encrypt_text(value) if value is not None else None

    @property
    def phone(self):
        return _decrypt_text(self.encrypted_phone) if self.encrypted_phone else None

    @phone.setter
    def phone(self, value):
        self.encrypted_phone = _encrypt_text(value) if value is not None else None

    @property
    def profile_picture(self):
        """
        Decrypt and return profile picture.
        First checks for profile_picture_blob (encrypted binary),
        then falls back to encrypted_profile_picture_path (for legacy or external URLs).
        Returns: bytes if BLOB exists, string path if path exists, None otherwise.
        """
        # If BLOB exists, return marker indicating we have a blob
        if self.profile_picture_blob:
            return f"blob://{self.id}"
        # Otherwise return decrypted path
        return _decrypt_text(self.encrypted_profile_picture_path) if self.encrypted_profile_picture_path else None

    @profile_picture.setter
    def profile_picture(self, value):
        """Encrypt and store profile picture path in DB (for OAuth or external URLs)."""
        if value is not None and isinstance(value, str):
            self.encrypted_profile_picture_path = _encrypt_text(value)
        else:
            self.encrypted_profile_picture_path = None

    def get_display_name(self):
        """Safe method to get display name that won't crash on encryption errors"""
        try:
            first = self.first_name or ""
            last = self.last_name or ""
            name = f"{first} {last}".strip()
            return name if name else self.username
        except Exception:
            return self.username

    @property
    def age(self):
        """Calculate age in years from date_of_birth if available."""
        try:
            if not self.date_of_birth:
                return None
            today = datetime.now(timezone.utc).date()
            dob = self.date_of_birth
            years = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            return years
        except Exception:
            return None
    def get_initials(self):
        """Get user initials for avatar display"""
        try:
            if self.first_name and self.last_name:
                return f"{self.first_name[0]}{self.last_name[0]}".upper()
            elif self.first_name:
                return self.first_name[0].upper()
            elif self.last_name:
                return self.last_name[0].upper()
            elif self.username:
                return self.username[0].upper()
            else:
                return 'U'
        except Exception:
            return 'U'


class PrescriptionAudit(db.Model):
    __tablename__ = 'prescription_audit'

    id = db.Column(db.Integer, primary_key=True)
    prescription_id = db.Column(db.Integer, db.ForeignKey('prescriptions.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(64), nullable=False)  # e.g., 'viewed','downloaded','printed','expired','dispensed'
    extra_info = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    prescription = db.relationship('Prescription', foreign_keys=[prescription_id])
    user = db.relationship('User', foreign_keys=[user_id])
        
class Patient(db.Model):
    __tablename__ = 'patients'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_emergency_contact = db.Column(db.LargeBinary)
    encrypted_insurance_provider = db.Column(db.LargeBinary)
    encrypted_insurance_number = db.Column(db.LargeBinary)
    encrypted_medical_history = db.Column(db.LargeBinary)
    encrypted_allergies = db.Column(db.LargeBinary)
    encrypted_current_medications = db.Column(db.LargeBinary)
    encrypted_blood_type = db.Column(db.LargeBinary)
    # Additional optional patient details
    encrypted_gender = db.Column(db.LargeBinary)
    encrypted_address = db.Column(db.LargeBinary)
    encrypted_city = db.Column(db.LargeBinary)
    encrypted_country = db.Column(db.LargeBinary)
    encrypted_postal_code = db.Column(db.LargeBinary)
    encrypted_occupation = db.Column(db.LargeBinary)
    encrypted_nationality = db.Column(db.LargeBinary)
    encrypted_marital_status = db.Column(db.LargeBinary)
    encrypted_height_cm = db.Column(db.LargeBinary)
    encrypted_weight_kg = db.Column(db.LargeBinary)
    encrypted_id_number = db.Column(db.LargeBinary)
    encrypted_preferred_language = db.Column(db.LargeBinary)

    appointments = db.relationship('Appointment', backref='patient', lazy=True)
    medical_records = db.relationship('MedicalRecord', backref='patient', lazy=True)

    @property
    def emergency_contact(self):
        return _decrypt_text(self.encrypted_emergency_contact) if self.encrypted_emergency_contact else None

    @emergency_contact.setter
    def emergency_contact(self, value):
        self.encrypted_emergency_contact = _encrypt_text(value) if value is not None else None

    @property
    def insurance_provider(self):
        return _decrypt_text(self.encrypted_insurance_provider) if self.encrypted_insurance_provider else None

    @insurance_provider.setter
    def insurance_provider(self, value):
        self.encrypted_insurance_provider = _encrypt_text(value) if value is not None else None

    @property
    def insurance_number(self):
        return _decrypt_text(self.encrypted_insurance_number) if self.encrypted_insurance_number else None

    @insurance_number.setter
    def insurance_number(self, value):
        self.encrypted_insurance_number = _encrypt_text(value) if value is not None else None

    @property
    def medical_history(self):
        return _decrypt_text(self.encrypted_medical_history) if self.encrypted_medical_history else None

    @medical_history.setter
    def medical_history(self, value):
        self.encrypted_medical_history = _encrypt_text(value) if value is not None else None

    @property
    def allergies(self):
        return _decrypt_text(self.encrypted_allergies) if self.encrypted_allergies else None

    @allergies.setter
    def allergies(self, value):
        self.encrypted_allergies = _encrypt_text(value) if value is not None else None

    @property
    def current_medications(self):
        return _decrypt_text(self.encrypted_current_medications) if self.encrypted_current_medications else None

    @current_medications.setter
    def current_medications(self, value):
        self.encrypted_current_medications = _encrypt_text(value) if value is not None else None

    @property
    def blood_type(self):
        return _decrypt_text(self.encrypted_blood_type) if self.encrypted_blood_type else None

    @blood_type.setter
    def blood_type(self, value):
        self.encrypted_blood_type = _encrypt_text(value) if value is not None else None

    @property
    def gender(self):
        return _decrypt_text(self.encrypted_gender) if self.encrypted_gender else None

    @gender.setter
    def gender(self, value):
        self.encrypted_gender = _encrypt_text(value) if value is not None else None

    @property
    def address(self):
        return _decrypt_text(self.encrypted_address) if self.encrypted_address else None

    @address.setter
    def address(self, value):
        self.encrypted_address = _encrypt_text(value) if value is not None else None

    @property
    def city(self):
        return _decrypt_text(self.encrypted_city) if self.encrypted_city else None

    @city.setter
    def city(self, value):
        self.encrypted_city = _encrypt_text(value) if value is not None else None

    @property
    def country(self):
        return _decrypt_text(self.encrypted_country) if self.encrypted_country else None

    @country.setter
    def country(self, value):
        self.encrypted_country = _encrypt_text(value) if value is not None else None

    @property
    def postal_code(self):
        return _decrypt_text(self.encrypted_postal_code) if self.encrypted_postal_code else None

    @postal_code.setter
    def postal_code(self, value):
        self.encrypted_postal_code = _encrypt_text(value) if value is not None else None

    @property
    def occupation(self):
        return _decrypt_text(self.encrypted_occupation) if self.encrypted_occupation else None

    @occupation.setter
    def occupation(self, value):
        self.encrypted_occupation = _encrypt_text(value) if value is not None else None

    @property
    def nationality(self):
        return _decrypt_text(self.encrypted_nationality) if self.encrypted_nationality else None

    @nationality.setter
    def nationality(self, value):
        self.encrypted_nationality = _encrypt_text(value) if value is not None else None

    @property
    def marital_status(self):
        return _decrypt_text(self.encrypted_marital_status) if self.encrypted_marital_status else None

    @marital_status.setter
    def marital_status(self, value):
        self.encrypted_marital_status = _encrypt_text(value) if value is not None else None

    @property
    def height_cm(self):
        v = _decrypt_text(self.encrypted_height_cm) if self.encrypted_height_cm else None
        try:
            return float(v) if v is not None and v != '' else None
        except Exception:
            return None

    @height_cm.setter
    def height_cm(self, value):
        self.encrypted_height_cm = _encrypt_text(str(value)) if value is not None else None

    @property
    def weight_kg(self):
        v = _decrypt_text(self.encrypted_weight_kg) if self.encrypted_weight_kg else None
        try:
            return float(v) if v is not None and v != '' else None
        except Exception:
            return None

    @weight_kg.setter
    def weight_kg(self, value):
        self.encrypted_weight_kg = _encrypt_text(str(value)) if value is not None else None

    @property
    def id_number(self):
        return _decrypt_text(self.encrypted_id_number) if self.encrypted_id_number else None

    @id_number.setter
    def id_number(self, value):
        self.encrypted_id_number = _encrypt_text(value) if value is not None else None

    @property
    def preferred_language(self):
        return _decrypt_text(self.encrypted_preferred_language) if self.encrypted_preferred_language else None

    @preferred_language.setter
    def preferred_language(self, value):
        self.encrypted_preferred_language = _encrypt_text(value) if value is not None else None

class Doctor(db.Model):
    __tablename__ = 'doctors'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_specialization = db.Column(db.LargeBinary)
    encrypted_license_number = db.Column(db.LargeBinary)
    encrypted_qualifications = db.Column(db.LargeBinary)
    encrypted_experience_years = db.Column(db.LargeBinary)
    encrypted_consultation_fee = db.Column(db.LargeBinary)
    availability = db.Column(db.Boolean, default=True)

    appointments = db.relationship('Appointment', backref='doctor', lazy=True)
    testimonials = db.relationship('Testimonial', backref='doctor', lazy='dynamic')

    def get_display_name(self):
        """Get doctor's display name"""
        try:
            # Use the associated user's display name if available
            if self.user:
                return self.user.get_display_name()
            # Fallback if user relationship isn't loaded
            elif hasattr(self, 'encrypted_first_name') and hasattr(self, 'encrypted_last_name'):
                # Try to decrypt directly if doctor has name fields (though they should be on user)
                first = _decrypt_text(self.encrypted_first_name) if self.encrypted_first_name else ""
                last = _decrypt_text(self.encrypted_last_name) if self.encrypted_last_name else ""
                name = f"{first} {last}".strip()
                return name if name else "Doctor"
            else:
                return "Doctor"
        except Exception:
            return "Doctor"

    @property
    def specialization(self):
        return _decrypt_text(self.encrypted_specialization) if self.encrypted_specialization else None

    @specialization.setter
    def specialization(self, value):
        self.encrypted_specialization = _encrypt_text(value) if value is not None else None

    @property
    def license_number(self):
        return _decrypt_text(self.encrypted_license_number) if self.encrypted_license_number else None

    @license_number.setter
    def license_number(self, value):
        self.encrypted_license_number = _encrypt_text(value) if value is not None else None

    @property
    def qualifications(self):
        return _decrypt_text(self.encrypted_qualifications) if self.encrypted_qualifications else None

    @qualifications.setter
    def qualifications(self, value):
        self.encrypted_qualifications = _encrypt_text(value) if value is not None else None

    @property
    def experience_years(self):
        v = _decrypt_text(self.encrypted_experience_years) if self.encrypted_experience_years else None
        return int(v) if v is not None and v != '' else None

    @experience_years.setter
    def experience_years(self, value):
        self.encrypted_experience_years = _encrypt_text(str(value)) if value is not None else None

    @property
    def consultation_fee(self):
        v = _decrypt_text(self.encrypted_consultation_fee) if self.encrypted_consultation_fee else None
        return float(v) if v is not None and v != '' else None

    @consultation_fee.setter
    def consultation_fee(self, value):
        self.encrypted_consultation_fee = _encrypt_text(str(value)) if value is not None else None

    @property
    def average_rating(self):
        try:
            avg = db.session.query(func.avg(Testimonial.rating)).filter(Testimonial.doctor_id == self.id).scalar()
            return round(float(avg), 2) if avg is not None else None
        except Exception:
            return None

# In models.py - Update the Appointment model if needed
# In models.py - Update the Appointment model

class Appointment(db.Model):
    __tablename__ = 'appointments'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, completed, cancelled, rescheduled
    consultation_type = db.Column(db.String(20))  # video, voice, message
    urgency = db.Column(db.String(20), default='routine')  # routine, urgent, emergency
    encrypted_symptoms = db.Column(db.LargeBinary)
    encrypted_notes = db.Column(db.LargeBinary)
    rating = db.Column(db.Integer, nullable=True)  # 1-5 stars
    encrypted_feedback = db.Column(db.LargeBinary)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    call_initiated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Track who initiated call
    call_status = db.Column(db.String(20), default='idle')  # idle, ringing, ongoing, missed, ended

    communications = db.relationship('Communication', backref='appointment', lazy=True)

    @property
    def symptoms(self):
        return _decrypt_text(self.encrypted_symptoms) if self.encrypted_symptoms else None

    @symptoms.setter
    def symptoms(self, value):
        self.encrypted_symptoms = _encrypt_text(value) if value is not None else None

    @property
    def notes(self):
        return _decrypt_text(self.encrypted_notes) if self.encrypted_notes else None

    @notes.setter
    def notes(self, value):
        self.encrypted_notes = _encrypt_text(value) if value is not None else None

    @property
    def feedback(self):
        return _decrypt_text(self.encrypted_feedback) if self.encrypted_feedback else None

    @feedback.setter
    def feedback(self, value):
        self.encrypted_feedback = _encrypt_text(value) if value is not None else None

class Communication(db.Model):
    __tablename__ = 'communications'

    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message_type = db.Column(db.String(20), nullable=False)  # text, voice_note, document, system, image, voice_call, video_call
    encrypted_content = db.Column(db.LargeBinary)
    encrypted_file_path = db.Column(db.LargeBinary)
    # Store binary blobs (encrypted) for recordings/uploads when needed
    encrypted_file_blob = db.Column(db.LargeBinary)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default=False)
    message_status = db.Column(db.String(20), default='sent')  # sent, delivered, read
    notification_sent = db.Column(db.Boolean, default=False)  # Whether notification was sent to recipient
    sound_enabled = db.Column(db.Boolean, default=True)  # Whether sound notification is enabled

    sender = db.relationship('User', foreign_keys=[sender_id])

    def __repr__(self):
        return f'<Communication {self.id}: {self.message_type}>'

    @property
    def content(self):
        return _decrypt_text(self.encrypted_content) if self.encrypted_content else None

    @content.setter
    def content(self, value):
        self.encrypted_content = _encrypt_text(value) if value is not None else None

    @property
    def file_path(self):
        return _decrypt_text(self.encrypted_file_path) if self.encrypted_file_path else None

    @file_path.setter
    def file_path(self, value):
        self.encrypted_file_path = _encrypt_text(value) if value is not None else None

class MedicalRecord(db.Model):
    __tablename__ = 'medical_records'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    record_type = db.Column(db.String(100), nullable=False)
    encrypted_file_path = db.Column(db.LargeBinary)
    encrypted_description = db.Column(db.LargeBinary)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def file_path(self):
        return _decrypt_text(self.encrypted_file_path) if self.encrypted_file_path else None

    @file_path.setter
    def file_path(self, value):
        self.encrypted_file_path = _encrypt_text(value) if value is not None else None

    @property
    def description(self):
        return _decrypt_text(self.encrypted_description) if self.encrypted_description else None

    @description.setter
    def description(self, value):
        self.encrypted_description = _encrypt_text(value) if value is not None else None


class PatientVital(db.Model):
    """Optional vitals model to store basic health metrics for patients.
    Add this table when you need to persist vitals like blood pressure,
    heart rate and temperature. Wrapped in try/except usage in views so
    code continues to work if the table isn't migrated yet.
    """
    __tablename__ = 'patient_vitals'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    recorded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    systolic = db.Column(db.Integer)
    diastolic = db.Column(db.Integer)
    heart_rate = db.Column(db.Integer)
    temperature = db.Column(db.Float)

    patient = db.relationship('Patient', backref='vitals')

class Testimonial(db.Model):
    __tablename__ = 'testimonials'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=True)
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    encrypted_content = db.Column(db.LargeBinary)
    is_public = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    patient = db.relationship('Patient', foreign_keys=[patient_id])

    @property
    def content(self):
        return _decrypt_text(self.encrypted_content) if self.encrypted_content else None

    @content.setter
    def content(self, value):
        self.encrypted_content = _encrypt_text(value) if value is not None else None


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class SocialAccount(db.Model):
    __tablename__ = 'social_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    provider = db.Column(db.String(50), nullable=False)  # 'google', 'facebook', 'twitter'
    provider_user_id = db.Column(db.String(255), nullable=False)
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = db.relationship('User', backref=db.backref('social_accounts', lazy=True))

    def __repr__(self):
        return f'<SocialAccount {self.provider}:{self.provider_user_id}>'


class Payment(db.Model):
    __tablename__ = 'payments'

    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=0.0)
    currency = db.Column(db.String(10), default='KES')
    provider = db.Column(db.String(50))
    provider_reference = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')  # pending, paid, failed, cancelled
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    appointment = db.relationship('Appointment', foreign_keys=[appointment_id])
    patient = db.relationship('Patient', foreign_keys=[patient_id])

    def mark_paid(self, provider_reference=None):
        try:
            self.status = 'paid'
            if provider_reference:
                self.provider_reference = provider_reference
            return True
        except Exception:
            return False

class PaymentLedger(db.Model):
    """Immutable-ish ledger of payment state changes per external transaction.
    Use external_payment_id (e.g., PSP transaction/intent id) as the natural key.
    """
    __tablename__ = 'payment_ledger'

    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.id'), nullable=True, index=True)
    external_payment_id = db.Column(db.String(255), nullable=False, unique=True, index=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=True)

    amount = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    provider = db.Column(db.String(50), nullable=True)

    # Canonical status: initiated, pending, succeeded, failed, refunded, cancelled
    status = db.Column(db.String(20), default='pending', nullable=False)

    # Raw last event payload for audit/debug (avoid PHI)
    raw_event = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    payment = db.relationship('Payment', foreign_keys=[payment_id])
    appointment = db.relationship('Appointment', foreign_keys=[appointment_id])
    patient = db.relationship('Patient', foreign_keys=[patient_id])


class WebhookEvent(db.Model):
    """Track processed webhook events for idempotency and auditing."""
    __tablename__ = 'webhook_events'

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)
    event_id = db.Column(db.String(255), nullable=False, unique=True, index=True)
    signature = db.Column(db.String(512))

    received_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    processed_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='received')  # received, processed, duplicate, failed
    error_message = db.Column(db.Text)
    raw_event = db.Column(db.JSON)


class IdempotencyKey(db.Model):
    """Store idempotency keys for API create/modify endpoints.
    This enables safe retries by returning the same response for the same key+request.
    """
    __tablename__ = 'idempotency_keys'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), nullable=False, unique=True, index=True)
    request_hash = db.Column(db.String(64), nullable=True, index=True)
    method = db.Column(db.String(10), nullable=True)
    path = db.Column(db.String(255), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    response_body = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=True)


class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=True)
    notification_type = db.Column(db.String(50), nullable=False)  # message, voice_call, video_call, missed_voice_call, missed_video_call, busy_voice_call, busy_video_call
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    title = db.Column(db.String(255))
    body = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    sound_enabled = db.Column(db.Boolean, default=True)
    call_status = db.Column(db.String(50), nullable=True)  # missed, busy, unanswered, connection_failed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('notifications', lazy=True))
    sender = db.relationship('User', foreign_keys=[sender_id])
    appointment = db.relationship('Appointment', backref=db.backref('notifications', lazy=True))


class PushSubscription(db.Model):
    """Stores Web Push subscriptions for users so server can send push messages reliably."""
    __tablename__ = 'push_subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    endpoint = db.Column(db.String(1024), nullable=False, unique=True)
    keys = db.Column(db.JSON)  # { p256dh: '', auth: '' }
    raw = db.Column(db.JSON)   # full subscription object for convenience
    user_agent = db.Column(db.String(512))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, onupdate=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('push_subscriptions', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'endpoint': self.endpoint,
            'keys': self.keys,
            'raw': self.raw,
            'user_agent': self.user_agent,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class CallSession(db.Model):
    __tablename__ = 'call_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=False)
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ended_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer)  # Duration in seconds
    call_quality = db.Column(db.String(20))  # excellent, good, poor
    participants = db.Column(db.JSON)  # Store participant info
    
    # Relationship
    appointment = db.relationship('Appointment', backref=db.backref('call_sessions', lazy=True))


class HealthTip(db.Model):
    __tablename__ = 'health_tips'
    
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=True)
    title = db.Column(db.String(255), nullable=False)
    encrypted_description = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    doctor = db.relationship('Doctor', backref=db.backref('health_tips', lazy=True))
    patient = db.relationship('Patient', backref=db.backref('health_tips', lazy=True))
    appointment = db.relationship('Appointment', backref=db.backref('health_tips', lazy=True))
    
    @property
    def description(self):
        """Decrypt description when accessed"""
        return _decrypt_text(self.encrypted_description) if self.encrypted_description else None
    
    @description.setter
    def description(self, value):
        """Encrypt description when set"""
        self.encrypted_description = _encrypt_text(value) if value is not None else None


# ============================================
# REAL-TIME COMMUNICATION MODELS
# ============================================

class CallHistory(db.Model):
    """Stores call history with full metadata for audit, analytics, and user replay"""
    __tablename__ = 'call_history'
    
    id = db.Column(db.Integer, primary_key=True)
    call_id = db.Column(db.String(64), unique=True, nullable=False, index=True)  # UUID from signaling
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=True)
    caller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    callee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    call_type = db.Column(db.String(10), nullable=False)  # 'video' or 'voice'
    
    # Call lifecycle timestamps
    initiated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    ringing_at = db.Column(db.DateTime)  # When callee was notified
    accepted_at = db.Column(db.DateTime)  # When callee accepted
    connected_at = db.Column(db.DateTime)  # When media established
    ended_at = db.Column(db.DateTime)
    
    # Call status: initiated, ringing, accepted, connecting, connected, ended, failed
    status = db.Column(db.String(20), nullable=False, default='initiated')
    # End reason: user_hangup, callee_declined, missed, busy, network_error, timeout, connection_failed
    end_reason = db.Column(db.String(30))
    
    # Duration in seconds (only set when ended)
    duration = db.Column(db.Integer)
    
    # SFU/Signaling room assignment
    room_id = db.Column(db.String(64))
    sfu_server = db.Column(db.String(255))  # Which SFU instance handled the call
    
    # Quality metrics (JSON: packet_loss, jitter, rtt, bitrate, cpu_usage, etc.)
    quality_metrics = db.Column(db.JSON)
    
    # Recording URL and metadata
    recording_url = db.Column(db.String(512))  # S3 or CDN URL
    recording_size = db.Column(db.BigInteger)  # In bytes
    recording_duration = db.Column(db.Integer)  # In seconds
    recording_consent = db.Column(db.Boolean, default=False)  # Was recording consented?
    
    # Participants metadata (for group calls or call details)
    participants_count = db.Column(db.Integer, default=2)
    
    # Audit trail
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    caller = db.relationship('User', foreign_keys=[caller_id], backref=db.backref('calls_as_caller', lazy=True))
    callee = db.relationship('User', foreign_keys=[callee_id], backref=db.backref('calls_as_callee', lazy=True))
    appointment = db.relationship('Appointment', backref=db.backref('call_history', lazy=True))
    
    def to_dict(self):
        """Serialize call history for API/UI consumption"""
        # Determine direction relative to current_user (if passed)
        from flask import current_user as cu
        direction = None
        remote_user = None
        if cu and cu.is_authenticated:
            if self.caller_id == cu.id:
                direction = 'outgoing'
                remote_user = self.callee
            elif self.callee_id == cu.id:
                direction = 'incoming'
                remote_user = self.caller
        
        return {
            'id': self.id,
            'call_id': self.call_id,
            'appointment_id': self.appointment_id,
            'caller_id': self.caller_id,
            'callee_id': self.callee_id,
            'call_type': self.call_type,
            'initiated_at': self.initiated_at.isoformat() if self.initiated_at else None,
            'connected_at': self.connected_at.isoformat() if self.connected_at else None,
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else self.initiated_at.isoformat() if self.initiated_at else None,
            'status': self.status,
            'end_reason': self.end_reason,
            'duration': self.duration,
            'direction': direction,
            'remote_user_name': remote_user.get_display_name() if remote_user else 'Unknown',
            'remote_user_avatar': remote_user.profile_picture if remote_user and hasattr(remote_user, 'profile_picture') else None,
            'call_note': f"{self.status}" if self.end_reason else self.status,
            'type': self.call_type,
            'recording_url': self.recording_url,
            'quality_metrics': self.quality_metrics
        }


class Conversation(db.Model):
    """Persistent conversations between users (1:1 or group)"""
    __tablename__ = 'conversations'
    
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(64), unique=True, nullable=False, index=True)  # UUID
    # Store participants as JSON array of user IDs for flexibility (can extend to group chats)
    participant_ids = db.Column(db.JSON, nullable=False)  # [user_id1, user_id2, ...]
    conversation_type = db.Column(db.String(20), default='direct')  # 'direct' or 'group'
    
    # For group conversations (optional)
    group_name = db.Column(db.String(255))
    group_avatar = db.Column(db.String(512))
    
    # Track conversation state
    last_message_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'conversation_id': self.conversation_id,
            'participant_ids': self.participant_ids,
            'conversation_type': self.conversation_type,
            'last_message_at': self.last_message_at.isoformat() if self.last_message_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Message(db.Model):
    """Individual messages in a conversation (encrypted at rest for privacy)"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(64), unique=True, nullable=False, index=True)  # UUID
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Message content (encrypted for HIPAA/GDPR compliance)
    encrypted_body = db.Column(db.LargeBinary)
    
    # Message type: text, image, file, voice_note, prescription, report
    message_type = db.Column(db.String(20), default='text')
    
    # In-call context (was this message sent during an active call?)
    in_call = db.Column(db.Boolean, default=False)
    call_id = db.Column(db.String(64))  # Reference to CallHistory.call_id
    
    # Message status: sent, delivered, read
    status = db.Column(db.String(20), default='sent')
    delivered_at = db.Column(db.DateTime)
    read_at = db.Column(db.DateTime)
    
    # Attachments and metadata
    attachment_ids = db.Column(db.JSON)  # Array of Attachment IDs
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    sender = db.relationship('User', backref=db.backref('sent_messages', lazy=True))
    
    @property
    def body(self):
        """Decrypt message body when accessed"""
        return _decrypt_text(self.encrypted_body) if self.encrypted_body else None
    
    @body.setter
    def body(self, value):
        """Encrypt message body when set"""
        self.encrypted_body = _encrypt_text(value) if value is not None else None
    
    def to_dict(self):
        return {
            'id': self.id,
            'message_id': self.message_id,
            'sender_id': self.sender_id,
            'body': self.body,
            'message_type': self.message_type,
            'status': self.status,
            'attachment_ids': self.attachment_ids,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Attachment(db.Model):
    """Files uploaded during calls or in-call chat (stored in S3)"""
    __tablename__ = 'attachments'
    
    id = db.Column(db.Integer, primary_key=True)
    attachment_id = db.Column(db.String(64), unique=True, nullable=False, index=True)  # UUID
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # File metadata
    file_name = db.Column(db.String(512), nullable=False)
    file_type = db.Column(db.String(50))  # MIME type: image/png, application/pdf, etc.
    file_size = db.Column(db.BigInteger)  # In bytes
    
    # Storage location
    s3_key = db.Column(db.String(512), nullable=False, unique=True)  # S3 object key
    s3_bucket = db.Column(db.String(255))  # S3 bucket name
    file_url = db.Column(db.String(512))  # CDN or signed URL for retrieval
    
    # Sharing context
    shared_in_call_id = db.Column(db.String(64))  # Reference to CallHistory.call_id
    shared_in_message_id = db.Column(db.Integer, db.ForeignKey('messages.id'))
    
    # Encrypted metadata (for sensitive files like medical records)
    encrypted_metadata = db.Column(db.LargeBinary)
    
    # Encryption for the file itself (at rest in S3)
    is_encrypted = db.Column(db.Boolean, default=True)
    
    # Access control
    access_control = db.Column(db.String(20), default='private')  # 'private', 'shared_call', 'shared_conversation'
    
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)  # Optional: auto-delete after X days
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    owner = db.relationship('User', backref=db.backref('uploaded_attachments', lazy=True))
    message = db.relationship('Message', backref=db.backref('attachments_rel', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'attachment_id': self.attachment_id,
            'file_name': self.file_name,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'file_url': self.file_url,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None
        }


class CallQualityMetrics(db.Model):
    """Detailed per-call quality metrics for monitoring and analytics"""
    __tablename__ = 'call_quality_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    call_id = db.Column(db.String(64), db.ForeignKey('call_history.call_id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Network metrics (sampled periodically during call)
    rtt = db.Column(db.Float)  # Round-trip time in ms
    packet_loss = db.Column(db.Float)  # % packet loss
    jitter = db.Column(db.Float)  # ms
    available_bandwidth = db.Column(db.Integer)  # kbps
    
    # Media metrics
    audio_bitrate = db.Column(db.Integer)  # kbps
    video_bitrate = db.Column(db.Integer)  # kbps
    video_resolution = db.Column(db.String(20))  # e.g., "1280x720"
    video_framerate = db.Column(db.Float)  # fps
    
    # System metrics
    cpu_usage = db.Column(db.Float)  # %
    memory_usage = db.Column(db.Float)  # %
    
    # Audio/video quality assessment
    audio_quality = db.Column(db.String(20))  # excellent, good, fair, poor
    video_quality = db.Column(db.String(20))
    
    # Timestamp (this metric point)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Relationships
    call = db.relationship('CallHistory', backref=db.backref('quality_metrics_detailed', lazy=True))
    user = db.relationship('User', backref=db.backref('call_quality_metrics', lazy=True))
    
    def to_dict(self):
        return {
            'rtt': self.rtt,
            'packet_loss': self.packet_loss,
            'jitter': self.jitter,
            'audio_bitrate': self.audio_bitrate,
            'video_bitrate': self.video_bitrate,
            'cpu_usage': self.cpu_usage,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class UserPresence(db.Model):
    """Track user online/offline status and current activity (soft real-time)"""
    __tablename__ = 'user_presence'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False, index=True)
    
    # Status: online, away, idle, busy, offline, do_not_disturb
    status = db.Column(db.String(20), default='offline')
    
    # Current activity context
    current_call_id = db.Column(db.String(64))  # UUID of active call if in one
    current_appointment_id = db.Column(db.Integer)  # Appointment ID if in appointment
    
    # Last activity timestamp (heartbeat)
    last_heartbeat = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Device info for mobile-aware presence
    device_type = db.Column(db.String(20))  # 'web', 'mobile', 'desktop'
    
    updated_at = db.Column(db.DateTime, onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    user = db.relationship('User', backref=db.backref('presence', uselist=False))
    
    def to_dict(self):
        return {
            'user_id': self.user_id,
            'status': self.status,
            'current_call_id': self.current_call_id,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }