# render_entry.py
import eventlet
eventlet.monkey_patch()

from app import app, socketio, db
from models import User, Patient, Doctor

if __name__ == '__main__':
    # Create tables and default users if they don't exist
    with app.app_context():
        try:
            db.create_all()
            print("✓ Database tables created/verified")
            
            # Create default users if they don't exist
            if not User.query.filter_by(username='admin').first():
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
                print("✓ Default admin created")
            
            if not User.query.filter_by(username='dr_mwangi').first():
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
                print("✓ Default doctor created")
            
            if not User.query.filter_by(username='patient').first():
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
                print("✓ Default patient created")
            
            db.session.commit()
            print("✓ Default users setup completed")
            
        except Exception as e:
            print(f"✗ Database initialization error: {e}")
            import traceback
            traceback.print_exc()

    # Run the app
    socketio.run(app, host='0.0.0.0', port=10000, debug=False)