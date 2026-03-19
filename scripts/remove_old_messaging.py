"""
Remove old messaging code blocks from app.py.
Preserves all non-messaging code (video calls, admin, general helpers).
"""
import re

INPUT  = r'c:\Users\makok\Desktop\TELEMED-WEBSITE-MMC\app.py'
OUTPUT = r'c:\Users\makok\Desktop\TELEMED-WEBSITE-MMC\app.py'

with open(INPUT, 'r', encoding='utf-8') as f:
    lines = f.readlines()

total = len(lines)
print(f"Original file: {total} lines")

# Build set of line numbers to REMOVE (0-indexed)
remove_ranges = []

def find_line(pattern, start=0):
    """Find first line idx (0-indexed) containing pattern after start."""
    for i in range(start, total):
        if pattern in lines[i]:
            return i
    return None

def find_func_end(def_line_idx):
    """Given the 0-indexed line of a 'def foo(...):' statement,
    find the exclusive end of the function body.
    A function ends when we encounter a non-blank, non-comment line at indent 0
    that isn't a continuation of the function, OR at EOF."""
    i = def_line_idx + 1
    last_body_line = def_line_idx  # track last meaningful body line
    while i < total:
        line = lines[i]
        stripped = line.strip()
        if stripped == '' or stripped.startswith('#'):
            # blank or comment — could be between functions, keep scanning
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            # This is a top-level statement — function ended before this
            return i
        last_body_line = i
        i += 1
    return total

def find_block_start(line_idx):
    """Walk backwards from a decorator/def to include preceding comment lines
    and blank lines that belong to this block."""
    i = line_idx - 1
    while i >= 0:
        stripped = lines[i].strip()
        if stripped.startswith('#') or stripped == '':
            i -= 1
        else:
            break
    return i + 1

def find_def_from(start):
    """Find the 'def ' line starting from start."""
    for i in range(start, total):
        stripped = lines[i].strip()
        if stripped.startswith('def '):
            return i
    return None

def remove_function_by_def(def_pattern, include_before=True):
    """Find a function by its def line pattern, include decorators/comments above,
    remove the entire block. Returns (start, end) or None."""
    ln = find_line(def_pattern)
    if ln is None:
        return None
    # Walk backwards to include decorators (@...) and comments
    start = ln
    while start > 0:
        prev = lines[start - 1].strip()
        if prev.startswith('@') or prev.startswith('#') or prev == '':
            start -= 1
        else:
            break
    if not include_before:
        start = ln
    end = find_func_end(ln)
    return (start, end)

def remove_function_by_route(route_pattern):
    """Find a function by its @app.route(...) decorator pattern."""
    ln = find_line(route_pattern)
    if ln is None:
        return None
    # The @app.route is the decorator. Walk backwards for comments.
    start = ln
    while start > 0:
        prev = lines[start - 1].strip()
        if prev.startswith('#') or prev == '':
            start -= 1
        else:
            break
    # Find the def line (may have multiple decorators)
    def_ln = find_def_from(ln)
    if def_ln is None:
        return None
    end = find_func_end(def_ln)
    return (start, end)

def remove_socket_handler(event_pattern):
    """Find a socket handler by its @socketio.on(...) pattern."""
    ln = find_line(event_pattern)
    if ln is None:
        return None
    start = ln
    while start > 0:
        prev = lines[start - 1].strip()
        if prev.startswith('#') or prev.startswith('# =') or prev == '':
            start -= 1
        else:
            break
    def_ln = find_def_from(ln)
    if def_ln is None:
        return None
    end = find_func_end(def_ln)
    return (start, end)

# ================================================================
# HTTP ROUTES TO REMOVE
# ================================================================

targets = []

# 1. get_messages
r = remove_function_by_route("@app.route('/api/messages/<int:appointment_id>')")
if r: targets.append(("get_messages", r))

# 2. send_message_http
r = remove_function_by_route("@app.route('/api/send-message'")
if r: targets.append(("send_message_http", r))

# 3. upload_file_api
r = remove_function_by_route("@app.route('/api/upload-file'")
if r: targets.append(("upload_file_api", r))

# 4. can_patient_access_messaging
r = remove_function_by_def("def can_patient_access_messaging(")
if r: targets.append(("can_patient_access_messaging", r))

# 5. _message_thread_ids
r = remove_function_by_def("def _message_thread_ids(")
if r: targets.append(("_message_thread_ids", r))

# 6. _reply_preview_content
r = remove_function_by_def("def _reply_preview_content(")
if r: targets.append(("_reply_preview_content", r))

# 7. _parse_receipt_data
r = remove_function_by_def("def _parse_receipt_data(")
if r: targets.append(("_parse_receipt_data", r))

# 8. _save_receipt_data
r = remove_function_by_def("def _save_receipt_data(")
if r: targets.append(("_save_receipt_data", r))

# 9. _record_message_receipt
r = remove_function_by_def("def _record_message_receipt(")
if r: targets.append(("_record_message_receipt", r))

# 10. send_message (the main /api/send_message route)
r = remove_function_by_route("@app.route('/api/send_message'")
if r: targets.append(("send_message", r))

# 11. edit_communication_message
r = remove_function_by_route("/api/messages/<int:message_id>/edit")
if r: targets.append(("edit_communication_message", r))

# 12. delete_communication_message
r = remove_function_by_route("/api/messages/<int:message_id>/delete")
if r: targets.append(("delete_communication_message", r))

# 13. update_message_receipt
r = remove_function_by_route("/api/messages/<int:message_id>/receipt")
if r: targets.append(("update_message_receipt", r))

# 14. get_message_receipts
r = remove_function_by_route("/api/messages/<int:message_id>/receipts")
if r: targets.append(("get_message_receipts", r))

# 15. get_appointment_messages_enhanced (/api/appointment/<id>/messages - GET)
r = remove_function_by_route("/api/appointment/<int:appointment_id>/messages')")
if r: targets.append(("get_appointment_messages_enhanced", r))

# 16. send_appointment_message (legacy POST /api/appointment/<id>/messages)
r = remove_function_by_route("/api/appointment/<int:appointment_id>/messages', methods=['POST']")
if r: targets.append(("send_appointment_message", r))

# 17. send_voice_note
r = remove_function_by_route("/api/appointment/<int:appointment_id>/voice-note")
if r: targets.append(("send_voice_note", r))

# 18. get_doctor_patient_messages
r = remove_function_by_route("/api/doctor/patient/<int:patient_id>/messages')")
if r: targets.append(("get_doctor_patient_messages", r))

# 19. send_doctor_message
r = remove_function_by_route("/api/doctor/patient/<int:patient_id>/messages', methods=['POST']")
if r: targets.append(("send_doctor_message", r))

# 20. get_patient_doctor_messages
r = remove_function_by_route("/api/patient/doctor/<int:doctor_id>/messages')")
if r: targets.append(("get_patient_doctor_messages", r))

# 21. send_patient_message
r = remove_function_by_route("/api/patient/doctor/<int:doctor_id>/messages', methods=['POST']")
if r: targets.append(("send_patient_message", r))

# ================================================================
# SOCKET.IO HANDLERS TO REMOVE
# ================================================================

# 22. message_delivered
r = remove_socket_handler("@socketio.on('message_delivered')")
if r: targets.append(("socket:message_delivered", r))

# 23. send_message
r = remove_socket_handler("@socketio.on('send_message')")
if r: targets.append(("socket:send_message", r))

# 24. message_read
r = remove_socket_handler("@socketio.on('message_read')")
if r: targets.append(("socket:message_read", r))

# 25. typing
r = remove_socket_handler("@socketio.on('typing')")
if r: targets.append(("socket:typing", r))

# 26. stop_typing
r = remove_socket_handler("@socketio.on('stop_typing')")
if r: targets.append(("socket:stop_typing", r))

# 27. voice_recording_status
r = remove_socket_handler("@socketio.on('voice_recording_status')")
if r: targets.append(("socket:voice_recording_status", r))

# 28. join_appointment
r = remove_socket_handler("@socketio.on('join_appointment')")
if r: targets.append(("socket:join_appointment", r))

# 29. leave_appointment
r = remove_socket_handler("@socketio.on('leave_appointment')")
if r: targets.append(("socket:leave_appointment", r))

# 30. chat:message
r = remove_socket_handler("@socketio.on('chat:message')")
if r: targets.append(("socket:chat:message", r))

# 31. chat:delivered
r = remove_socket_handler("@socketio.on('chat:delivered')")
if r: targets.append(("socket:chat:delivered", r))

# 32. chat:read
r = remove_socket_handler("@socketio.on('chat:read')")
if r: targets.append(("socket:chat:read", r))

# ================================================================
# Apply removals
# ================================================================

# Sort targets by start line for display
targets.sort(key=lambda t: t[1][0])

# Print summary
print(f"\n{'='*60}")
print(f"Blocks to remove ({len(targets)}):")
print(f"{'='*60}")
for name, (start, end) in targets:
    print(f"  {name:40s} lines {start+1:5d} - {end:5d}  ({end - start:3d} lines)")

# Build removal set
remove_set = set()
for name, (start, end) in targets:
    for i in range(start, end):
        remove_set.add(i)

print(f"\nTotal lines to remove: {len(remove_set)}")

# Safety: verify none of the KEEP functions overlap with removal
keep_funcs = [
    "def verify_appointment_access(",
    "def is_consultation_paid(",
    "def get_appointment_payment_status(",
    "def _stream_communication_file(",
    "def _signed_comm_download_url_for_user(",
    "def get_signed_communication_url(",
    "def download_communication_file_signed(",
    "def download_communication_file(",
    "def _batched_appointment_comm_meta(",
    "def get_patient_doctors(",
    "def get_user_basic(",
    "def get_patient_latest_appointment(",
    "def get_doctor_latest_appointment(",
    "def start_consultation(",
    "def handle_disconnect(",
    "def health_check(",
    "def handle_user_online_status(",
]

print(f"\nSafety check - verifying KEEP functions are not removed:")
safe = True
for func in keep_funcs:
    ln = find_line(func)
    if ln is not None and ln in remove_set:
        print(f"  *** DANGER: {func.strip()} at line {ln+1} IS IN REMOVAL SET ***")
        safe = False
    elif ln is not None:
        print(f"  OK: {func.strip()} at line {ln+1}")
    else:
        print(f"  SKIP: {func.strip()} (not found)")

if not safe:
    print("\n*** ABORTING - some KEEP functions would be removed! ***")
    exit(1)

# Write cleaned file
new_lines = []
for i, line in enumerate(lines):
    if i not in remove_set:
        new_lines.append(line)

with open(OUTPUT, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"\nDone! New file: {len(new_lines)} lines (removed {total - len(new_lines)} lines)")
