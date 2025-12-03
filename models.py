from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    date_of_birth = db.Column(db.Date)
    profile_picture = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    # Per-role toggles persisted on the user record
    # - `allow_user_creation` (admin only): whether this admin may create other users via admin UI
    # - `show_availability` (doctor only): whether the doctor's availability is shown publicly
    # - `share_data` (patient only): whether the patient consents to share anonymized data
    allow_user_creation = db.Column(db.Boolean, default=False)
    show_availability = db.Column(db.Boolean, default=True)
    share_data = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
            today = datetime.utcnow().date()
            dob = self.date_of_birth
            years = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            return years
        except Exception:
            return None

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    message_type = db.Column(db.String(20), nullable=False)  # text, voice_note, document, system, image
    encrypted_content = db.Column(db.LargeBinary)
    encrypted_file_path = db.Column(db.LargeBinary)
    # Store binary blobs (encrypted) for recordings/uploads when needed
    encrypted_file_blob = db.Column(db.LargeBinary)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    # WhatsApp-style message status: sent, delivered, read
    message_status = db.Column(db.String(20), default='sent')  # sent, delivered, read
    # For typing indicators (temporary, not stored in DB)
    # We'll handle typing via Socket.IO events
    
    sender = db.relationship('User', foreign_keys=[sender_id])

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class SocialAccount(db.Model):
    __tablename__ = 'social_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    provider = db.Column(db.String(50), nullable=False)  # 'google', 'facebook', 'twitter'
    provider_user_id = db.Column(db.String(255), nullable=False)
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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

class CallSession(db.Model):
    __tablename__ = 'call_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer)  # Duration in seconds
    call_quality = db.Column(db.String(20))  # excellent, good, poor
    participants = db.Column(db.JSON)  # Store participant info
    
    # Relationship
    appointment = db.relationship('Appointment', backref=db.backref('call_sessions', lazy=True))