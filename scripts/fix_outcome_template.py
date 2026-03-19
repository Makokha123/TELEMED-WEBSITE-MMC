import re

with open('templates/email/appointment_outcome.html', encoding='utf-8') as f:
    content = f.read()

# Replace url_for with login_url
content = re.sub(r"url_for\('patient_dashboard', _external=True\)", 'login_url', content)

# Fix remaining doctor_user name references  
content = re.sub(
    r"\{\{\s*doctor_user\.title\s+or\s+'Dr\.'?\s*\}\}\s*\{\{\s*doctor_user\.first_name\s*\}\}\s*\{\{\s*doctor_user\.last_name\s*\}\}",
    '{{ doctor_name or "Your Doctor" }}',
    content
)

with open('templates/email/appointment_outcome.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Done')
for i, line in enumerate(content.splitlines(), 1):
    if 'user.first_name' in line or 'user.title' in line or 'doctor_user.first_name' in line or 'doctor.practitioner' in line or "url_for('patient_dashboard'" in line:
        print(f'ISSUE L{i}: {line}')
