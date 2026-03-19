"""
Fix all HTML linting errors (inline styles → CSS classes, accessibility attributes).
Run from project root: python scripts/fix_html_errors.py
"""
import re

# ─────────────────────────────────────────
# 1. APPEND NEW CSS CLASSES TO style.css
# ─────────────────────────────────────────
CSS_ADDITIONS = """

/* ============================================================
   UTILITY CLASSES (consolidated from inline styles)
   ============================================================ */

/* Hidden by default; JS controls visibility via .style.display */
.initially-hidden { display: none; }

/* Cursor helper */
.cursor-pointer { cursor: pointer; }

/* Call logs panel wrapper (absolute overlay) */
.call-logs-panel-wrapper {
    position: absolute;
    top: 24px;
    right: 24px;
    width: 360px;
    z-index: 40;
}

/* Outgoing call modals */
.call-modal-gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.call-modal-avatar-wrap { margin-bottom: 30px; }
.call-modal-avatar-circle {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    margin: 0 auto 20px;
    background: rgba(255,255,255,0.2);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 48px;
    font-weight: bold;
}
.call-modal-name   { margin-bottom: 10px; }
.call-modal-subtext{ margin: 0; opacity: 0.9; }
.call-modal-spinner-wrap { margin: 40px 0; }
.call-spinner-lg   { width: 60px; height: 60px; }
.call-modal-actions{
    margin-top: 40px;
    display: flex;
    gap: 10px;
    justify-content: center;
}
.btn-call-end-circle {
    border-radius: 50%;
    width: 60px;
    height: 60px;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
}
.icon-fs-24 { font-size: 24px; }

/* Call-logs header button */
.btn-call-logs-header {
    margin-right: 6px;
    background: linear-gradient(135deg, #198754 0%, #157347 100%);
    color: #fff;
    border: none;
}
.btn-call-logs-header:hover {
    background: linear-gradient(135deg, #157347 0%, #0f5132 100%);
    color: #fff;
}

/* Admin contact dropdown (replaces all its inline styles) */
.admin-dropdown {
    display: none;
    position: absolute;
    top: 60px;
    right: 20px;
    background: white;
    border: 1px solid #e5e5e5;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    z-index: 1000;
    min-width: 250px;
}
.admin-contact-dropdown-header { padding: 12px; border-bottom: 1px solid #e5e5e5; }
.admin-contact-dropdown-title  { margin: 0; font-weight: 600; color: #111b21; }
.admin-contact-list            { max-height: 300px; overflow-y: auto; }
.admin-list-placeholder        { padding: 12px; text-align: center; color: #999; }

/* User menu float */
.user-menu-float { position: absolute; z-index: 1050; display: none; }

/* Doctor dashboard helpers */
.profile-header-end {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 10px;
}
.avatar-img-lg    { width: 64px;  height: 64px;  border-radius: 50%; object-fit: cover; }
.appt-patient-img { width: 50px;  height: 50px;  border-radius: 50%; object-fit: cover; }
.activity-user-img{
    width: 32px; height: 32px;
    border-radius: 50%;
    object-fit: cover;
    flex-shrink: 0;
}
.activity-user-initial {
    width: 32px; height: 32px;
    border-radius: 50%;
    background: linear-gradient(135deg, #28a745, #20c997);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    font-size: 0.8em;
    flex-shrink: 0;
}
.activity-icon-w  { width: 32px; }
.activity-text-sm { font-size: 0.9em; }
.recent-patient-avatar {
    width: 45px; height: 45px;
    border-radius: 50%;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    overflow: hidden;
}
.recent-patient-avatar img { width: 100%; height: 100%; object-fit: cover; }

/* Modal header colour variants */
.modal-header-green      { background: linear-gradient(135deg, #28a745, #20c997); color: white; }
.modal-header-amber      { background: linear-gradient(135deg, #ffc107, #ff9800); color: white; }
.modal-header-danger-bg  { background-color: #dc3545; color: white; }

/* Report stat metric values */
.stat-metric        { font-size: 24px; font-weight: bold; }
.stat-metric-blue   { color: #007bff; }
.stat-metric-green  { color: #28a745; }
.stat-metric-yellow { color: #ffc107; }
.stat-metric-cyan   { color: #0dcaf0; }
.stat-metric-purple { color: #6f42c1; }
.stat-metric-orange { color: #ff9800; }
.stat-metric-red    { color: #e74c3c; }
.table-row-alt      { background-color: #f8f9fa; }
"""

with open('static/css/style.css', 'a', encoding='utf-8') as f:
    f.write(CSS_ADDITIONS)
print('✓ style.css updated')


# ─────────────────────────────────────────
# 2. HELPERS
# ─────────────────────────────────────────
def read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()

def write(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


# ─────────────────────────────────────────
# 3. FIX testimonials.html
# ─────────────────────────────────────────
path = 'templates/testimonials.html'
html = read(path)

# display:none → class
html = html.replace(
    '<div id="avgContainer" class="mb-3" style="display:none;">',
    '<div id="avgContainer" class="mb-3 initially-hidden">'
)
# add title to select
html = html.replace(
    '<select id="doctorFilter" class="form-select">',
    '<select id="doctorFilter" class="form-select" title="Filter by doctor" aria-label="Filter by doctor">'
)

write(path, html)
print('✓ testimonials.html fixed')


# ─────────────────────────────────────────
# 4. FIX doctor/communication.html
# ─────────────────────────────────────────
path = 'templates/doctor/communication.html'
html = read(path)

# back-to-list
html = html.replace(
    '<div class="back-to-list" id="backToList" style="display: none;">',
    '<div class="back-to-list initially-hidden" id="backToList">'
)
# call-logs header btn
html = html.replace(
    '<button class="chat-action-btn" id="openCallLogsHeaderBtn" title="Call logs" data-bs-toggle="modal" data-bs-target="#callLogsModal" style="margin-right:6px; background: linear-gradient(135deg,#198754 0%,#157347 100%); color: #fff; border: none;">',
    '<button class="chat-action-btn btn-call-logs-header" id="openCallLogsHeaderBtn" title="Call logs" data-bs-toggle="modal" data-bs-target="#callLogsModal">'
)
# typing indicator
html = html.replace(
    '<div class="typing-indicator" id="typingIndicator" style="display: none;">',
    '<div class="typing-indicator initially-hidden" id="typingIndicator">'
)
# file input
html = html.replace(
    '<input type="file" id="fileInput" style="display: none;" accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,.txt,.xlsx,.mp3,.wav,.mp4">',
    '<input type="file" id="fileInput" class="initially-hidden" accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,.txt,.xlsx,.mp3,.wav,.mp4">'
)
# emoji picker btn – add title
html = html.replace(
    '<button class="input-emoji-btn" id="emojiPickerBtn">',
    '<button class="input-emoji-btn" id="emojiPickerBtn" title="Emoji" aria-label="Emoji">'
)
# recording UI
html = html.replace(
    '<div class="recording-ui" id="recordingUI" style="display: none;">',
    '<div class="recording-ui initially-hidden" id="recordingUI">'
)
# call logs panel wrapper
html = html.replace(
    '        <div style="position: absolute; top: 24px; right: 24px; width: 360px; z-index: 40;">',
    '        <div class="call-logs-panel-wrapper">'
)
# payment overlay
html = html.replace(
    '<div class="payment-overlay" id="paymentOverlay" style="display: none;">',
    '<div class="payment-overlay initially-hidden" id="paymentOverlay">'
)
# admin dropdown (full inline style block)
html = html.replace(
    '<div class="admin-dropdown" id="adminDropdown" style="display: none; position: absolute; top: 60px; right: 20px; background: white; border: 1px solid #e5e5e5; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); z-index: 1000; min-width: 250px;">',
    '<div class="admin-dropdown" id="adminDropdown">'
)
html = html.replace(
    '    <div style="padding: 12px; border-bottom: 1px solid #e5e5e5;">\n        <h6 style="margin: 0; font-weight: 600; color: #111b21;">Contact Support</h6>',
    '    <div class="admin-contact-dropdown-header">\n        <h6 class="admin-contact-dropdown-title">Contact Support</h6>'
)
# admin list container
html = html.replace(
    '    <div id="adminListContainer" style="max-height: 300px; overflow-y: auto;">',
    '    <div id="adminListContainer" class="admin-contact-list">'
)
html = html.replace(
    '        <div style="padding: 12px; text-align: center; color: #999;">\n            <i class="fas fa-spinner fa-spin"></i> Loading admins...',
    '        <div class="admin-list-placeholder">\n            <i class="fas fa-spinner fa-spin"></i> Loading admins...'
)
# voice player
html = html.replace(
    '<audio id="voicePlayer" style="display: none;"></audio>',
    '<audio id="voicePlayer" class="initially-hidden"></audio>'
)
# btn-close buttons without aria-label
html = re.sub(
    r'<button type="button" class="btn-close" data-bs-dismiss="modal">',
    '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close">',
    html
)
# outgoing video call modal content bg
html = html.replace(
    '                    <div class="modal-content border-0" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">\n                        <div class="modal-body text-center text-white py-5">\n                            <div style="margin-bottom: 30px;">\n                                <div class="avatar-large" id="outgoingVideoDoctorAvatar" style="width: 120px; height: 120px; border-radius: 50%; margin: 0 auto 20px; background: rgba(255,255,255,0.2); display: flex; align-items: center; justify-content: center; font-size: 48px; font-weight: bold;">',
    '                    <div class="modal-content border-0 call-modal-gradient-bg">\n                        <div class="modal-body text-center text-white py-5">\n                            <div class="call-modal-avatar-wrap">\n                                <div class="avatar-large call-modal-avatar-circle" id="outgoingVideoDoctorAvatar">'
)
html = html.replace(
    '                                <h5 id="outgoingVideoDoctorName" style="margin-bottom: 10px;">Patient Name</h5>\n                                <p style="margin: 0; opacity: 0.9;">Video call in progress...</p>',
    '                                <h5 id="outgoingVideoDoctorName" class="call-modal-name">Patient Name</h5>\n                                <p class="call-modal-subtext">Video call in progress...</p>'
)
html = html.replace(
    '                            <div style="margin: 40px 0;">\n                                <div class="spinner-border text-light" role="status" style="width: 60px; height: 60px;">\n                                    <span class="visually-hidden">Calling...</span>\n                                </div>\n                            </div>\n                            <div style="margin-top: 40px; display: flex; gap: 10px; justify-content: center;">\n                                <button type="button" class="btn btn-danger btn-lg" id="rejectOutgoingVideoCallBtn" style="border-radius: 50%; width: 60px; height: 60px; padding: 0; display: flex; align-items: center; justify-content: center;">\n                                    <i class="fas fa-phone-slash" style="font-size: 24px;"></i>\n                                </button>\n                            </div>',
    '                            <div class="call-modal-spinner-wrap">\n                                <div class="spinner-border text-light call-spinner-lg" role="status">\n                                    <span class="visually-hidden">Calling...</span>\n                                </div>\n                            </div>\n                            <div class="call-modal-actions">\n                                <button type="button" class="btn btn-danger btn-lg btn-call-end-circle" id="rejectOutgoingVideoCallBtn" aria-label="End call">\n                                    <i class="fas fa-phone-slash icon-fs-24"></i>\n                                </button>\n                            </div>'
)
# outgoing voice call modal content bg
html = html.replace(
    '                    <div class="modal-content border-0" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">\n                        <div class="modal-body text-center text-white py-5">\n                            <div style="margin-bottom: 30px;">\n                                <div class="avatar-large" id="outgoingVoiceDoctorAvatar" style="width: 120px; height: 120px; border-radius: 50%; margin: 0 auto 20px; background: rgba(255,255,255,0.2); display: flex; align-items: center; justify-content: center; font-size: 48px; font-weight: bold;">',
    '                    <div class="modal-content border-0 call-modal-gradient-bg">\n                        <div class="modal-body text-center text-white py-5">\n                            <div class="call-modal-avatar-wrap">\n                                <div class="avatar-large call-modal-avatar-circle" id="outgoingVoiceDoctorAvatar">'
)
html = html.replace(
    '                                <h5 id="outgoingVoiceDoctorName" style="margin-bottom: 10px;">Patient Name</h5>\n                                <p style="margin: 0; opacity: 0.9;">Calling...</p>',
    '                                <h5 id="outgoingVoiceDoctorName" class="call-modal-name">Patient Name</h5>\n                                <p class="call-modal-subtext">Calling...</p>'
)
html = html.replace(
    '                            <div style="margin: 40px 0;">\n                                <div class="spinner-border text-light" role="status" style="width: 60px; height: 60px;">\n                                    <span class="visually-hidden">Calling...</span>\n                                </div>\n                            </div>\n                            <div style="margin-top: 40px; display: flex; gap: 10px; justify-content: center;">\n                                <button type="button" class="btn btn-danger btn-lg" id="rejectOutgoingVoiceCallBtn" style="border-radius: 50%; width: 60px; height: 60px; padding: 0; display: flex; align-items: center; justify-content: center;">\n                                    <i class="fas fa-phone-slash" style="font-size: 24px;"></i>\n                                </button>\n                            </div>',
    '                            <div class="call-modal-spinner-wrap">\n                                <div class="spinner-border text-light call-spinner-lg" role="status">\n                                    <span class="visually-hidden">Calling...</span>\n                                </div>\n                            </div>\n                            <div class="call-modal-actions">\n                                <button type="button" class="btn btn-danger btn-lg btn-call-end-circle" id="rejectOutgoingVoiceCallBtn" aria-label="End call">\n                                    <i class="fas fa-phone-slash icon-fs-24"></i>\n                                </button>\n                            </div>'
)

write(path, html)
print('✓ templates/doctor/communication.html fixed')


# ─────────────────────────────────────────
# 5. FIX patient/communication.html
# ─────────────────────────────────────────
path = 'templates/patient/communication.html'
html = read(path)

# back-to-list
html = html.replace(
    '<div class="back-to-list" id="backToList" style="display: none;">',
    '<div class="back-to-list initially-hidden" id="backToList">'
)
# call-logs header btn
html = html.replace(
    '<button class="chat-action-btn" id="openCallLogsHeaderBtn" title="Call logs" data-bs-toggle="modal" data-bs-target="#callLogsModal" style="margin-right:6px; background: linear-gradient(135deg,#198754 0%,#157347 100%); color: #fff; border: none;">',
    '<button class="chat-action-btn btn-call-logs-header" id="openCallLogsHeaderBtn" title="Call logs" data-bs-toggle="modal" data-bs-target="#callLogsModal">'
)
# typing indicator
html = html.replace(
    '<div class="typing-indicator" id="typingIndicator" style="display: none;">',
    '<div class="typing-indicator initially-hidden" id="typingIndicator">'
)
# file input
html = html.replace(
    '<input type="file" id="fileInput" style="display: none;" accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,.txt,.xlsx,.mp3,.wav,.mp4">',
    '<input type="file" id="fileInput" class="initially-hidden" accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,.txt,.xlsx,.mp3,.wav,.mp4">'
)
# emoji picker btn
html = html.replace(
    '<button class="input-emoji-btn" id="emojiPickerBtn">',
    '<button class="input-emoji-btn" id="emojiPickerBtn" title="Emoji" aria-label="Emoji">'
)
# recording UI
html = html.replace(
    '<div class="recording-ui" id="recordingUI" style="display: none;">',
    '<div class="recording-ui initially-hidden" id="recordingUI">'
)
# payment overlay
html = html.replace(
    '<div class="payment-overlay" id="paymentOverlay" style="display: none;">',
    '<div class="payment-overlay initially-hidden" id="paymentOverlay">'
)
# admin dropdown
html = html.replace(
    '<div class="admin-dropdown" id="adminDropdown" style="display: none; position: absolute; top: 60px; right: 20px; background: white; border: 1px solid #e5e5e5; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); z-index: 1000; min-width: 250px;">',
    '<div class="admin-dropdown" id="adminDropdown">'
)
html = html.replace(
    '            <div style="padding: 12px; border-bottom: 1px solid #e5e5e5;">\n                <h6 style="margin: 0; font-weight: 600; color: #111b21;">Contact Support</h6>',
    '            <div class="admin-contact-dropdown-header">\n                <h6 class="admin-contact-dropdown-title">Contact Support</h6>'
)
html = html.replace(
    '            <div id="adminListContainer" style="max-height: 300px; overflow-y: auto;">',
    '            <div id="adminListContainer" class="admin-contact-list">'
)
html = html.replace(
    '                <div style="padding: 12px; text-align: center; color: #999;">\n                    <i class="fas fa-spinner fa-spin"></i> Loading admins...',
    '                <div class="admin-list-placeholder">\n                    <i class="fas fa-spinner fa-spin"></i> Loading admins...'
)
# call logs panel wrapper
html = html.replace(
    '        <div style="position: absolute; top: 24px; right: 24px; width: 360px; z-index: 40;">',
    '        <div class="call-logs-panel-wrapper">'
)
# user menu float
html = html.replace(
    '<div class="dropdown" id="userMenuDropdown" style="position: absolute; z-index: 1050; display:none;">',
    '<div class="dropdown user-menu-float" id="userMenuDropdown">'
)
# voice player
html = html.replace(
    '<audio id="voicePlayer" style="display: none;"></audio>',
    '<audio id="voicePlayer" class="initially-hidden"></audio>'
)
# btn-close buttons
html = re.sub(
    r'<button type="button" class="btn-close" data-bs-dismiss="modal">',
    '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close">',
    html
)
# outgoing video call modal
html = html.replace(
    '    <div class="modal-content border-0" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">\n        <div class="modal-body text-center text-white py-5">\n            <div style="margin-bottom: 30px;">\n                <div class="avatar-large" id="outgoingVideoDoctorAvatar" style="width: 120px; height: 120px; border-radius: 50%; margin: 0 auto 20px; background: rgba(255,255,255,0.2); display: flex; align-items: center; justify-content: center; font-size: 48px; font-weight: bold;">',
    '    <div class="modal-content border-0 call-modal-gradient-bg">\n        <div class="modal-body text-center text-white py-5">\n            <div class="call-modal-avatar-wrap">\n                <div class="avatar-large call-modal-avatar-circle" id="outgoingVideoDoctorAvatar">'
)
html = html.replace(
    '                    <h5 id="outgoingVideoDoctorName" style="margin-bottom: 10px;">Doctor Name</h5>\n                    <p style="margin: 0; opacity: 0.9;">Video call in progress...</p>',
    '                    <h5 id="outgoingVideoDoctorName" class="call-modal-name">Doctor Name</h5>\n                    <p class="call-modal-subtext">Video call in progress...</p>'
)
html = html.replace(
    '                <div style="margin: 40px 0;">\n                    <div class="spinner-border text-light" role="status" style="width: 60px; height: 60px;">\n                        <span class="visually-hidden">Calling...</span>\n                    </div>\n                </div>\n                <div style="margin-top: 40px; display: flex; gap: 10px; justify-content: center;">\n                    <button type="button" class="btn btn-danger btn-lg" id="rejectOutgoingVideoCallBtn" style="border-radius: 50%; width: 60px; height: 60px; padding: 0; display: flex; align-items: center; justify-content: center;">\n                        <i class="fas fa-phone-slash" style="font-size: 24px;"></i>\n                    </button>\n                </div>',
    '                <div class="call-modal-spinner-wrap">\n                    <div class="spinner-border text-light call-spinner-lg" role="status">\n                        <span class="visually-hidden">Calling...</span>\n                    </div>\n                </div>\n                <div class="call-modal-actions">\n                    <button type="button" class="btn btn-danger btn-lg btn-call-end-circle" id="rejectOutgoingVideoCallBtn" aria-label="End call">\n                        <i class="fas fa-phone-slash icon-fs-24"></i>\n                    </button>\n                </div>'
)
# outgoing voice call modal
html = html.replace(
    '    <div class="modal-content border-0" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">\n        <div class="modal-body text-center text-white py-5">\n            <div style="margin-bottom: 30px;">\n                <div class="avatar-large" id="outgoingVoiceDoctorAvatar" style="width: 120px; height: 120px; border-radius: 50%; margin: 0 auto 20px; background: rgba(255,255,255,0.2); display: flex; align-items: center; justify-content: center; font-size: 48px; font-weight: bold;">',
    '    <div class="modal-content border-0 call-modal-gradient-bg">\n        <div class="modal-body text-center text-white py-5">\n            <div class="call-modal-avatar-wrap">\n                <div class="avatar-large call-modal-avatar-circle" id="outgoingVoiceDoctorAvatar">'
)
html = html.replace(
    '                    <h5 id="outgoingVoiceDoctorName" style="margin-bottom: 10px;">Doctor Name</h5>\n                    <p style="margin: 0; opacity: 0.9;">Calling...</p>',
    '                    <h5 id="outgoingVoiceDoctorName" class="call-modal-name">Doctor Name</h5>\n                    <p class="call-modal-subtext">Calling...</p>'
)
html = html.replace(
    '                <div style="margin: 40px 0;">\n                    <div class="spinner-border text-light" role="status" style="width: 60px; height: 60px;">\n                        <span class="visually-hidden">Calling...</span>\n                    </div>\n                </div>\n                <div style="margin-top: 40px; display: flex; gap: 10px; justify-content: center;">\n                    <button type="button" class="btn btn-danger btn-lg" id="rejectOutgoingVoiceCallBtn" style="border-radius: 50%; width: 60px; height: 60px; padding: 0; display: flex; align-items: center; justify-content: center;">\n                        <i class="fas fa-phone-slash" style="font-size: 24px;"></i>\n                    </button>\n                </div>',
    '                <div class="call-modal-spinner-wrap">\n                    <div class="spinner-border text-light call-spinner-lg" role="status">\n                        <span class="visually-hidden">Calling...</span>\n                    </div>\n                </div>\n                <div class="call-modal-actions">\n                    <button type="button" class="btn btn-danger btn-lg btn-call-end-circle" id="rejectOutgoingVoiceCallBtn" aria-label="End call">\n                        <i class="fas fa-phone-slash icon-fs-24"></i>\n                    </button>\n                </div>'
)

write(path, html)
print('✓ templates/patient/communication.html fixed')


# ─────────────────────────────────────────
# 6. FIX doctor/doctor_dashboard.html
# ─────────────────────────────────────────
path = 'templates/doctor/doctor_dashboard.html'
html = read(path)

# profile header wrapper
html = html.replace(
    '<div style="display:flex;align-items:center;justify-content:flex-end;gap:10px;">',
    '<div class="profile-header-end">'
)
# profile picture img
html = html.replace(
    'style="width:64px;height:64px;border-radius:50%;object-fit:cover;"',
    'class="avatar-img-lg"'
)
# file input
html = html.replace(
    '<input type="file" name="file" id="doctorProfileFile" accept="image/*" style="display:none;" />',
    '<input type="file" name="file" id="doctorProfileFile" accept="image/*" class="initially-hidden" />'
)
# cursor pointer on quick-action cards
html = html.replace(
    'data-bs-toggle="modal" data-bs-target="#prescriptionModal" style="cursor: pointer;">',
    'data-bs-toggle="modal" data-bs-target="#prescriptionModal" style="" class="cursor-pointer">'.replace(' style=""', '')
)
html = html.replace(
    'data-bs-toggle="modal" data-bs-target="#reportsModal" style="cursor: pointer;">',
    'data-bs-toggle="modal" data-bs-target="#reportsModal" style="" class="cursor-pointer">'.replace(' style=""', '')
)
# appointment patient image
html = html.replace(
    'style="width:50px;height:50px;border-radius:50%;object-fit:cover;"',
    'class="appt-patient-img"'
)
# recent activity: user img
html = html.replace(
    'style="width:32px;height:32px;border-radius:50%;object-fit:cover;flex-shrink:0;"',
    'class="activity-user-img"'
)
# recent activity: user initial div
html = html.replace(
    'style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#28a745,#20c997);color:white;display:flex;align-items:center;justify-content:center;font-weight:bold;font-size:0.8em;flex-shrink:0;"',
    'class="activity-user-initial"'
)
# recent activity: icon width
html = html.replace(
    ' text-primary me-2 flex-shrink-0" style="width:32px;">',
    ' text-primary me-2 flex-shrink-0 activity-icon-w">'
)
# recent activity text
html = html.replace(
    '<span style="font-size:0.9em;">{{ act.text }}</span>',
    '<span class="activity-text-sm">{{ act.text }}</span>'
)
# recent patients avatar
html = html.replace(
    '<div class="patient-avatar" style="width: 45px; height: 45px; border-radius: 50%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; display: flex; align-items: center; justify-content: center; font-weight: bold; overflow: hidden;">',
    '<div class="recent-patient-avatar">'
)
# recent patients avatar img
html = html.replace(
    'style="width: 100%; height: 100%; object-fit: cover;">',
    'class="recent-patient-avatar-img">'
)
# modal headers
html = html.replace(
    '<div class="modal-header" style="background: linear-gradient(135deg, #28a745, #20c997); color: white;">',
    '<div class="modal-header modal-header-green">'
)
html = html.replace(
    '<div class="modal-header" style="background: linear-gradient(135deg, #ffc107, #ff9800); color: white;">',
    '<div class="modal-header modal-header-amber">'
)
html = html.replace(
    '<div class="modal-header" style="background-color: #dc3545; color: white;">',
    '<div class="modal-header modal-header-danger-bg">'
)
# stat metric values
html = html.replace(
    '<div style="font-size: 24px; font-weight: bold; color: #007bff;" id="totalConsultations">0</div>',
    '<div class="stat-metric stat-metric-blue" id="totalConsultations">0</div>'
)
html = html.replace(
    '<div style="font-size: 24px; font-weight: bold; color: #28a745;" id="avgRating">4.8</div>',
    '<div class="stat-metric stat-metric-green" id="avgRating">4.8</div>'
)
html = html.replace(
    '<div style="font-size: 24px; font-weight: bold; color: #28a745;" id="totalRevenue">Ksh 0</div>',
    '<div class="stat-metric stat-metric-green" id="totalRevenue">Ksh 0</div>'
)
html = html.replace(
    '<div style="font-size: 24px; font-weight: bold; color: #ffc107;" id="avgConsultationFee">Ksh 0</div>',
    '<div class="stat-metric stat-metric-yellow" id="avgConsultationFee">Ksh 0</div>'
)
html = html.replace(
    '<div style="font-size: 24px; font-weight: bold; color: #0dcaf0;" id="totalPrescriptions">0</div>',
    '<div class="stat-metric stat-metric-cyan" id="totalPrescriptions">0</div>'
)
html = html.replace(
    '<div style="font-size: 24px; font-weight: bold; color: #6f42c1;" id="avgMedsPerPrescription">0</div>',
    '<div class="stat-metric stat-metric-purple" id="avgMedsPerPrescription">0</div>'
)
html = html.replace(
    '<div style="font-size: 24px; font-weight: bold; color: #ff9800;" id="totalUniquePatients">0</div>',
    '<div class="stat-metric stat-metric-orange" id="totalUniquePatients">0</div>'
)
html = html.replace(
    '<div style="font-size: 24px; font-weight: bold; color: #e74c3c;" id="newPatientsCount">0</div>',
    '<div class="stat-metric stat-metric-red" id="newPatientsCount">0</div>'
)
# table row alternate
html = html.replace(
    '<tr style="background-color: #f8f9fa;">',
    '<tr class="table-row-alt">'
)
# datetime-local input: add aria-label
html = html.replace(
    '<input type="datetime-local" class="form-control" value="2024-01-20T10:00">',
    '<input type="datetime-local" class="form-control" value="2024-01-20T10:00" aria-label="Appointment date and time">'
)

# Fix the <ul> with direct non-li children (Jinja template issue)
# The validator flags the {% if %} / {% else %} blocks directly inside <ul>
# Fix: wrap the entire conditional outside the <ul> by splitting into two <ul> blocks
old_ul = '''                            <ul class="list-unstyled">
                                    {% if recent_activity %}
                                        {% for act in recent_activity %}
                                            <li class="d-flex align-items-center gap-2 mb-2">'''
new_ul = '''                            {% if recent_activity %}
                            <ul class="list-unstyled">
                                        {% for act in recent_activity %}
                                            <li class="d-flex align-items-center gap-2 mb-2">'''
if old_ul in html:
    html = html.replace(old_ul, new_ul)
    # Also fix the closing part
    old_close = '''                                        {% endfor %}
                                    {% else %}
                                        <li class="text-muted">No recent activity</li>
                                    {% endif %}
                                </ul>'''
    new_close = '''                                        {% endfor %}
                            </ul>
                            {% else %}
                            <ul class="list-unstyled">
                                        <li class="text-muted">No recent activity</li>
                            </ul>
                            {% endif %}'''
    html = html.replace(old_close, new_close)
    print('  → Fixed <ul> structure')
else:
    print('  → <ul> pattern not found (may need manual check)')

write(path, html)
print('✓ templates/doctor/doctor_dashboard.html fixed')


# ─────────────────────────────────────────
# 7. VERIFY: check for remaining issues
# ─────────────────────────────────────────
import os
files_to_check = [
    'templates/testimonials.html',
    'templates/doctor/communication.html',
    'templates/patient/communication.html',
    'templates/doctor/doctor_dashboard.html',
]
print('\n--- Remaining inline styles check ---')
for fp in files_to_check:
    content = read(fp)
    # Find remaining style= attributes (rough check)
    remaining = re.findall(r'style="[^"]{5,}"', content)
    if remaining:
        print(f'{fp}: {len(remaining)} inline style(s) remain:')
        for s in remaining[:5]:
            print(f'   {s[:80]}')
    else:
        print(f'{fp}: clean ✓')

print('\nDone!')
