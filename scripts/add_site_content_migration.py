"""
Migration: Create site_content table and seed default values.
Run once:  python scripts/add_site_content_migration.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import SiteContent

DEFAULTS = [
    # ── Branding / Global ──
    ('branding', 'site_name', 'Makokha Medical Centre', 'text'),
    ('branding', 'site_tagline', 'Telemedicine & Clinical Services', 'text'),
    ('branding', 'logo_url', '', 'image'),
    ('branding', 'primary_color', '#0d6efd', 'color'),
    ('branding', 'secondary_color', '#198754', 'color'),
    ('branding', 'accent_color', '#6f42c1', 'color'),
    ('branding', 'footer_bg_color', '#212529', 'color'),

    # ── Hero Section (index.html) ──
    ('hero', 'badge_text', 'Secure Telemedicine Platform', 'text'),
    ('hero', 'title', 'Quality Healthcare From The Comfort Of Your Home', 'text'),
    ('hero', 'subtitle', 'MAKOKHA MEDICAL CENTRE brings expert medical care to you through our advanced telemedicine platform. Connect with certified healthcare professionals anytime, anywhere.', 'text'),
    ('hero', 'cta_primary_text', 'Get Started Free', 'text'),
    ('hero', 'cta_secondary_text', 'How It Works', 'text'),
    ('hero', 'trust_badge_1', 'No registration fees', 'text'),
    ('hero', 'trust_badge_2', 'HIPAA compliant', 'text'),
    ('hero', 'trust_badge_3', '24/7 Support', 'text'),
    ('hero', 'carousel_image_1', '', 'image'),
    ('hero', 'carousel_caption_1_title', 'Video Consultations', 'text'),
    ('hero', 'carousel_caption_1_text', 'Connect face-to-face with certified doctors from home', 'text'),
    ('hero', 'carousel_caption_2_title', 'E-Prescriptions', 'text'),
    ('hero', 'carousel_caption_2_text', 'Get prescriptions sent directly to your pharmacy', 'text'),
    ('hero', 'carousel_caption_3_title', 'Easy Scheduling', 'text'),
    ('hero', 'carousel_caption_3_text', 'Book appointments in minutes, see a doctor today', 'text'),

    # ── Stats Section (index.html) ──
    ('stats', 'satisfaction_rate', '95', 'text'),

    # ── Features Section (index.html) ──
    ('features', 'section_title', 'Why Choose Our Telemedicine Platform?', 'text'),
    ('features', 'section_subtitle', 'Experience healthcare that comes to you with our comprehensive telemedicine solutions', 'text'),
    ('features', 'feature_1_icon', 'fas fa-video', 'text'),
    ('features', 'feature_1_title', 'Video Consultations', 'text'),
    ('features', 'feature_1_text', 'Face-to-face virtual appointments with board-certified doctors from the comfort of your home.', 'text'),
    ('features', 'feature_2_icon', 'fas fa-file-medical', 'text'),
    ('features', 'feature_2_title', 'Digital Prescriptions', 'text'),
    ('features', 'feature_2_text', 'Get prescriptions sent directly to your pharmacy without visiting a physical clinic.', 'text'),
    ('features', 'feature_3_icon', 'fas fa-shield-alt', 'text'),
    ('features', 'feature_3_title', 'Secure & Private', 'text'),
    ('features', 'feature_3_text', 'Your health information is protected with enterprise-grade security and HIPAA compliance.', 'text'),

    # ── Health Tips Section (index.html) ──
    ('health_tips', 'section_title', 'Health Tips & Guidance', 'text'),
    ('health_tips', 'section_subtitle', 'Expert advice to keep you and your family healthy', 'text'),
    ('health_tips', 'tip_1_badge', 'Nutrition', 'text'),
    ('health_tips', 'tip_1_badge_color', 'success', 'text'),
    ('health_tips', 'tip_1_icon', 'fas fa-apple-alt', 'text'),
    ('health_tips', 'tip_1_title', 'Boost Your Immunity Naturally', 'text'),
    ('health_tips', 'tip_1_text', 'A balanced diet rich in vitamins C & D, zinc, and antioxidants strengthens your immune system. Include citrus fruits, leafy greens, and nuts in your daily meals.', 'text'),
    ('health_tips', 'tip_2_badge', 'Wellness', 'text'),
    ('health_tips', 'tip_2_badge_color', 'primary', 'text'),
    ('health_tips', 'tip_2_icon', 'fas fa-heartbeat', 'text'),
    ('health_tips', 'tip_2_title', 'Managing Stress in the Digital Age', 'text'),
    ('health_tips', 'tip_2_text', 'Practice mindfulness, take regular screen breaks, and maintain a consistent sleep schedule. Even 10 minutes of daily meditation can reduce anxiety significantly.', 'text'),
    ('health_tips', 'tip_3_badge', 'Telemedicine', 'text'),
    ('health_tips', 'tip_3_badge_color', 'info', 'text'),
    ('health_tips', 'tip_3_icon', 'fas fa-laptop-medical', 'text'),
    ('health_tips', 'tip_3_title', 'When to Use Telemedicine', 'text'),
    ('health_tips', 'tip_3_text', 'Telemedicine is ideal for follow-ups, prescription refills, mental health sessions, and non-emergency consultations. Save time and get care from home.', 'text'),

    # ── CTA Section (index.html) ──
    ('cta', 'title', 'Ready to Experience Modern Healthcare?', 'text'),
    ('cta', 'subtitle', 'Join thousands of patients who have transformed their healthcare experience with our telemedicine platform.', 'text'),

    # ── FAQ Section (index.html) ──
    ('faq', 'section_title', 'Frequently Asked Questions', 'text'),
    ('faq', 'section_subtitle', 'Get answers to common questions about our telemedicine services', 'text'),
    ('faq', 'faq_1_q', 'How does telemedicine work?', 'text'),
    ('faq', 'faq_1_a', 'Telemedicine allows you to consult with healthcare providers remotely using video, voice, or messaging. You can schedule appointments, have virtual consultations, receive prescriptions, and get medical advice without visiting a physical clinic.', 'text'),
    ('faq', 'faq_2_q', 'Is telemedicine secure and private?', 'text'),
    ('faq', 'faq_2_a', 'Yes, we use enterprise-grade security measures including end-to-end encryption, secure servers, and comply with HIPAA regulations to ensure your health information remains private and secure.', 'text'),
    ('faq', 'faq_3_q', 'Can I get prescriptions through telemedicine?', 'text'),
    ('faq', 'faq_3_a', 'Yes, our licensed healthcare providers can prescribe medications when appropriate. Prescriptions are sent electronically to your preferred pharmacy for convenient pickup.', 'text'),
    ('faq', 'faq_4_q', 'What equipment do I need for a telemedicine appointment?', 'text'),
    ('faq', 'faq_4_a', 'You need a smartphone, tablet, or computer with a camera and microphone, plus a stable internet connection. Our platform works on all major browsers and devices.', 'text'),

    # ── Contact Section (index.html) ──
    ('contact', 'section_title', 'Contact Us', 'text'),
    ('contact', 'section_subtitle', "We're here to help — reach out via phone, WhatsApp or message.", 'text'),
    ('contact', 'phone_1', '+254 741256531', 'text'),
    ('contact', 'phone_2', '+254 713580997', 'text'),
    ('contact', 'whatsapp_1', '254741256531', 'text'),
    ('contact', 'whatsapp_1_display', '0741256531', 'text'),
    ('contact', 'whatsapp_2', '254713580997', 'text'),
    ('contact', 'whatsapp_2_display', '0713580997', 'text'),
    ('contact', 'email', 'makokhamedicalcentre@gmail.com', 'text'),
    ('contact', 'facebook_handle', '@makokhamedical', 'text'),
    ('contact', 'facebook_url', 'https://facebook.com/makokhamedical', 'text'),
    ('contact', 'telegram_handle', '@makokhamedical', 'text'),
    ('contact', 'telegram_url', 'https://t.me/makokhamedical', 'text'),
    ('contact', 'instagram_handle', '@makokhamedical', 'text'),
    ('contact', 'instagram_url', 'https://instagram.com/makokhamedical', 'text'),
    ('contact', 'twitter_handle', '@makokhamedicaltelemed', 'text'),
    ('contact', 'twitter_url', 'https://twitter.com/makokhamedical', 'text'),
    ('contact', 'emergency_number', '911', 'text'),

    # ── Footer (base.html) ──
    ('footer', 'description', 'Providing quality telemedicine services for all your healthcare needs.', 'text'),
    ('footer', 'copyright', '2025 MAKOKHA MEDICAL CENTRE. All rights reserved.', 'text'),
    ('footer', 'info_email', 'info@makokhamedical.com', 'text'),

    # ── About Page ──
    ('about', 'hero_title', 'About MAKOKHA MEDICAL CENTRE', 'text'),
    ('about', 'hero_subtitle', 'Delivering trusted telemedicine services with compassion and clinical excellence.', 'text'),
    ('about', 'mission_title', 'Our Mission', 'text'),
    ('about', 'mission_text', 'To make quality healthcare accessible to everyone by combining experienced clinicians, patient-centred care, and secure telemedicine technology.', 'text'),
    ('about', 'offer_title', 'What We Offer', 'text'),
    ('about', 'offer_items', '["Video and voice consultations with certified doctors","Secure messaging and medical record sharing","Prescription delivery and follow-up care","Specialist referrals and continuity of care"]', 'json'),
    ('about', 'values_title', 'Our Values', 'text'),
    ('about', 'values_text', 'Quality, Privacy, Accessibility, and Compassion guide every interaction we have with our patients.', 'text'),
    ('about', 'hero_image', '', 'image'),

    # ── Services Page ──
    ('services', 'section_title', 'Our Services', 'text'),
    ('services', 'section_subtitle', 'We offer both remote telemedicine services and in-facility care for patients who can visit us.', 'text'),
    ('services', 'telemedicine_title', 'Telemedicine Services', 'text'),
    ('services', 'telemedicine_description', 'Access quality healthcare from anywhere. Our telemedicine platform connects you with certified doctors for consultations, follow-ups, and prescriptions.', 'text'),
    ('services', 'telemedicine_items', '["Video consultations","Voice consultations","Secure messaging with clinicians","E-prescriptions and medication management","Remote monitoring and follow-up","Online referrals and test ordering"]', 'json'),
    ('services', 'facility_title', 'In-Facility Services', 'text'),
    ('services', 'facility_description', 'Visit our medical centre for hands-on care. Our facility is equipped with modern diagnostic and treatment equipment.', 'text'),
    ('services', 'facility_items', '["In-person specialist consultations","Laboratory tests and imaging","Minor procedures and wound care","Pharmacy and medication pickup","Vaccinations and preventive services","Emergency and urgent care"]', 'json'),

    # ── Doctors Page ──
    ('doctors_page', 'section_title', 'Our Doctors', 'text'),
    ('doctors_page', 'section_subtitle', 'Browse our team of certified medical professionals', 'text'),

    # ── Consultation Room Settings ──
    ('consultation_settings', 'open_before_minutes', '0', 'text'),
    ('consultation_settings', 'open_after_minutes', '0', 'text'),
]

def run():
    with app.app_context():
        # Create table
        SiteContent.__table__.create(bind=db.engine, checkfirst=True)
        print('✓ site_content table created (or already exists)')

        # Seed defaults (skip existing)
        added = 0
        for section, key, value, ctype in DEFAULTS:
            existing = SiteContent.query.filter_by(section=section, key=key).first()
            if not existing:
                entry = SiteContent(section=section, key=key, value=value, content_type=ctype)
                db.session.add(entry)
                added += 1
        db.session.commit()
        print(f'✓ Seeded {added} default content entries ({len(DEFAULTS)} total defined)')

if __name__ == '__main__':
    run()
