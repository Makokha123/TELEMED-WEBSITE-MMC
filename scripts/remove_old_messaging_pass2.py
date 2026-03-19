"""
Remove remaining old messaging routes from app.py (second pass).
"""

INPUT = r'c:\Users\makok\Desktop\TELEMED-WEBSITE-MMC\app.py'
OUTPUT = r'c:\Users\makok\Desktop\TELEMED-WEBSITE-MMC\app.py'

with open(INPUT, 'r', encoding='utf-8') as f:
    lines = f.readlines()

total = len(lines)
print(f"Current file: {total} lines")

def find_line(pattern, start=0):
    for i in range(start, total):
        if pattern in lines[i]:
            return i
    return None

def find_func_end(def_line_idx):
    """Find where a top-level def block ends (exclusive)."""
    i = def_line_idx + 1
    while i < total:
        line = lines[i]
        stripped = line.strip()
        if stripped == '' or stripped.startswith('#'):
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            return i
        i += 1
    return total

def find_def_from(start):
    for i in range(start, total):
        stripped = lines[i].strip()
        if stripped.startswith('def '):
            return i
    return None

targets = []

# 1. get_appointment_messages_enhanced
ln = find_line("@app.route('/api/appointment/<int:appointment_id>/messages', methods=['GET'])")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip().startswith('#') or lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("get_appointment_messages_enhanced", (start, end)))

# 2. send_appointment_message (legacy)
ln = find_line("@app.route('/api/send-message-legacy'")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip().startswith('#') or lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("send_appointment_message", (start, end)))

# 3. send_voice_note
ln = find_line("@app.route('/api/send-voice-note'")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip().startswith('#') or lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("send_voice_note", (start, end)))

# 4. get_doctor_patient_messages
ln = find_line("@app.route('/api/doctor/patient/<int:patient_id>/messages', methods=['GET'])")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("get_doctor_patient_messages", (start, end)))

# 5. send_doctor_message
ln = find_line("@app.route('/api/doctor/send-message'")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("send_doctor_message", (start, end)))

# 6. get_patient_doctor_messages
ln = find_line("@app.route('/api/patient/doctor/<int:doctor_id>/messages', methods=['GET'])")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("get_patient_doctor_messages", (start, end)))

# 7. send_patient_message
ln = find_line("@app.route('/api/patient/send-message'")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("send_patient_message", (start, end)))

# 8. get_appointment_messages_api (duplicate at end of file)
ln = find_line("@app.route('/api/appointment-messages/<int:appointment_id>'")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip().startswith('#') or lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("get_appointment_messages_api", (start, end)))

# 9. get_appointment_unread_count (covered by new blueprint)
ln = find_line("@app.route('/api/appointment/<int:appointment_id>/unread-count'")
if ln is not None:
    start = ln
    while start > 0 and (lines[start-1].strip() == ''):
        start -= 1
    def_ln = find_def_from(ln)
    end = find_func_end(def_ln)
    targets.append(("get_appointment_unread_count", (start, end)))

# Sort and display
targets.sort(key=lambda t: t[1][0])

print(f"\nBlocks to remove ({len(targets)}):")
for name, (start, end) in targets:
    print(f"  {name:45s} lines {start+1:5d} - {end:5d}  ({end - start:3d} lines)")

# Build removal set
remove_set = set()
for name, (start, end) in targets:
    for i in range(start, end):
        remove_set.add(i)

print(f"\nTotal lines to remove: {len(remove_set)}")

# Safety check KEEP functions
keep_funcs = [
    "def get_patient_latest_appointment(",
    "def get_doctor_latest_appointment(",
    "def start_consultation(",
    "def get_patient_doctors(",
    "def get_user_basic(",
    "def verify_appointment_access(",
    "def notifications_page(",
    "def get_user_permissions(",
]

print("\nSafety check:")
safe = True
for func in keep_funcs:
    ln = find_line(func)
    if ln is not None and ln in remove_set:
        print(f"  *** DANGER: {func.strip()} at line {ln+1} IS IN REMOVAL SET ***")
        safe = False
    elif ln is not None:
        print(f"  OK: {func.strip()} at line {ln+1}")

if not safe:
    print("\n*** ABORTING ***")
    exit(1)

# Write
new_lines = [line for i, line in enumerate(lines) if i not in remove_set]
with open(OUTPUT, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"\nDone! New file: {len(new_lines)} lines (removed {total - len(new_lines)} lines)")
