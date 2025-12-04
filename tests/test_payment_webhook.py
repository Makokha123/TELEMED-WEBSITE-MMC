import json
import hmac
import hashlib
from datetime import datetime, timezone

import pytest

from app import app, db
from models import User, Patient, Doctor, Appointment, Payment


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['PAYMENT_PROVIDER_SECRETS'] = {'mpesa': 'testsecret'}

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def create_minimal_entities():
    # Creates minimal User/Patient/Doctor/Appointment/Payment records
    u = User(username='patient1')
    u.email = 'patient1@example.com'
    u.set_password('password')
    u.first_name = 'Patient'
    u.last_name = 'One'
    db.session.add(u)
    db.session.commit()

    patient = Patient(user_id=u.id)
    db.session.add(patient)
    db.session.commit()

    du = User(username='doc1')
    du.email = 'doc1@example.com'
    du.set_password('password')
    du.first_name = 'Doc'
    du.last_name = 'One'
    du.role = 'doctor'
    db.session.add(du)
    db.session.commit()

    doctor = Doctor(user_id=du.id)
    db.session.add(doctor)
    db.session.commit()

    appt = Appointment(patient_id=patient.id, doctor_id=doctor.id, appointment_date=datetime.now(timezone.utc))
    db.session.add(appt)
    db.session.commit()

    payment = Payment(appointment_id=appt.id, patient_id=patient.id, amount=100.0, currency='KES', status='pending')
    db.session.add(payment)
    db.session.commit()

    return payment


def test_mpesa_webhook_marks_payment_paid(client):
    with app.app_context():
        payment = create_minimal_entities()
        payload = {'payment_id': payment.id, 'status': 'paid', 'provider_reference': 'tx123'}
        raw = json.dumps(payload).encode('utf-8')
        sig = hmac.new(b'testsecret', raw, hashlib.sha256).hexdigest()

        resp = client.post('/payment/webhook/mpesa', data=raw, content_type='application/json', headers={'X-Signature': sig})
        assert resp.status_code == 200

        # Refresh from DB
        try:
            p = db.session.get(Payment, payment.id)
        except Exception:
            p = db.session.get(Payment, payment.id)
        assert p is not None
        assert p.status == 'paid'
        assert p.provider_reference == 'tx123'
