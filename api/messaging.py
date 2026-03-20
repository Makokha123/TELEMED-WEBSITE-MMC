"""
Messaging Blueprint – Doctor ↔ Patient real-time chat
=====================================================
Single source of truth for all messaging REST endpoints and Socket.IO handlers.
Uses the Communication model (appointment-scoped, encrypted at rest).

Features:
  - Real-time send/receive via Socket.IO with HTTP fallback
  - Message statuses: sent → delivered → read (live tick marks)
  - Read receipts (bulk mark-as-read)
  - Typing indicators with auto-timeout
  - Reply-to messages
  - File / voice-note attachments (encrypted at rest)
  - Online/offline presence per appointment room
  - Rate limiting (30 msg/min)
  - Payment gating for patients
  - Idempotent message sends (client_msg_id)
  - Signed URLs for secure file downloads
"""

import os, time, uuid, hashlib, hmac
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Blueprint, request, jsonify, current_app, send_file, abort, url_for
)
from flask_login import login_required, current_user
from flask_socketio import emit, join_room, leave_room
from io import BytesIO

from models import (
    db, Communication, Appointment, Patient, Doctor, User, Payment,
    _encrypt_text, _decrypt_text, encrypt_file_bytes, decrypt_file_bytes
)

messaging_bp = Blueprint('messaging', __name__, url_prefix='/api/messaging')

# ---------------------------------------------------------------------------
#  Shared state (injected from app.py via init_messaging)
# ---------------------------------------------------------------------------
_socketio = None
_csrf = None
_rate_limits = {}
_idempotency_cache = {}
_redis_client_fn = None
_user_sockets = {}

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf', 'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'audio/webm', 'audio/ogg', 'audio/mpeg', 'audio/mp4', 'audio/wav',
}
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
MAX_MESSAGE_LENGTH = 5000
RATE_LIMIT_MESSAGES = 30          # per minute
SIGNED_URL_TTL = 300              # 5 min

_SIGNED_URL_SECRET = os.getenv('SIGNED_URL_SECRET', os.getenv('SECRET_KEY', 'change-me'))


# ═══════════════════════════════════════════════════════════════════════════
#  INITIALIZER — called once from app.py
# ═══════════════════════════════════════════════════════════════════════════

def init_messaging(socketio, csrf, redis_fn, user_sockets, rate_limits, idempotency_cache):
    global _socketio, _csrf, _redis_client_fn, _user_sockets, _rate_limits, _idempotency_cache
    _socketio = socketio
    _csrf = csrf
    _redis_client_fn = redis_fn
    _user_sockets = user_sockets
    _rate_limits = rate_limits
    _idempotency_cache = idempotency_cache
    _register_socket_handlers(socketio)


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _redis():
    """Get Redis client (may be None)."""
    try:
        return _redis_client_fn() if _redis_client_fn else None
    except Exception:
        return None


def _room(appointment_id):
    """Canonical Socket.IO room name for an appointment chat."""
    return f'appointment_{appointment_id}'


def _rate_limit_check(user_id, key, limit, window):
    """Return True if allowed, False if rate-limited."""
    try:
        now_ts = time.time()
        r = _redis()
        if r:
            bucket = f'rl:{key}:{user_id}:{int(now_ts // window)}'
            count = r.incr(bucket)
            r.expire(bucket, int(window) + 2)
            return count <= limit
        # In-memory fallback
        bucket = _rate_limits.get((user_id, key), [])
        bucket = [t for t in bucket if now_ts - t < window]
        if len(bucket) >= limit:
            _rate_limits[(user_id, key)] = bucket
            return False
        bucket.append(now_ts)
        _rate_limits[(user_id, key)] = bucket
        return True
    except Exception:
        return True


def _idempotency_get(user_id, client_id):
    if not client_id:
        return None
    import json
    key = f'idempo:{user_id}:{client_id}'
    try:
        r = _redis()
        if r:
            raw = r.get(key)
            if raw:
                return json.loads(raw)
    except Exception:
        pass
    return _idempotency_cache.get(key)


def _idempotency_set(user_id, client_id, value, ttl=600):
    if not client_id:
        return
    import json
    key = f'idempo:{user_id}:{client_id}'
    _idempotency_cache[key] = value
    try:
        r = _redis()
        if r:
            r.setex(key, ttl, json.dumps(value, default=str))
    except Exception:
        pass


def _is_online(user_id):
    """Check if a user has active socket connections."""
    sids = _user_sockets.get(user_id)
    if sids:
        return len(sids) > 0 if isinstance(sids, list) else True
    try:
        r = _redis()
        if r:
            return bool(r.scard(f'user_sockets:{user_id}'))
    except Exception:
        pass
    return False


def _verify_access(appointment, user):
    """Check user has access to appointment. Returns True/False."""
    if user.role == 'admin':
        return True
    if user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=user.id).first()
        return doctor and appointment.doctor_id == doctor.id
    if user.role == 'patient':
        patient = Patient.query.filter_by(user_id=user.id).first()
        return patient and appointment.patient_id == patient.id
    return False


def _check_payment(appointment_id, user):
    """Return True if patient messaging is blocked by unpaid payment."""
    if user.role != 'patient':
        return False
    try:
        appt = db.session.get(Appointment, appointment_id)
        if appt and getattr(appt, 'payment_status', None) == 'unpaid':
            return True
    except Exception:
        pass
    return False


def _get_display_name(user):
    if user and hasattr(user, 'get_display_name'):
        return user.get_display_name()
    return 'Unknown'


def _get_initials(user):
    name = _get_display_name(user)
    parts = name.split()
    return ''.join(p[0].upper() for p in parts[:2]) if parts else '?'


def _sign_url(message_id, user_id, ttl=SIGNED_URL_TTL):
    """Generate HMAC-signed download token."""
    expires = int(time.time()) + ttl
    payload = f'{message_id}:{user_id}:{expires}'
    sig = hmac.new(_SIGNED_URL_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f'{sig}:{expires}'


def _verify_signed_url(message_id, user_id, token):
    """Verify HMAC-signed token. Returns True if valid."""
    try:
        sig, expires_str = token.rsplit(':', 1)
        expires = int(expires_str)
        if time.time() > expires:
            return False
        payload = f'{message_id}:{user_id}:{expires}'
        expected = hmac.new(_SIGNED_URL_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def _reply_preview(msg):
    """Generate truncated preview for reply-to display."""
    if not msg:
        return ''
    text = msg.content or ''
    if msg.message_type == 'voice_note':
        text = '🎤 Voice note'
    elif msg.message_type == 'image':
        text = '📷 Image'
    elif msg.message_type == 'document':
        text = '📎 ' + (msg.content or 'Document')
    elif msg.message_type == 'system':
        text = msg.content or 'System message'
    return text[:120] + ('…' if len(text) > 120 else '')


def _serialize(msg, include_reply=True):
    """Serialize a Communication record to JSON dict."""
    sender = msg.sender
    data = {
        'id': msg.id,
        'appointment_id': msg.appointment_id,
        'sender_id': msg.sender_id,
        'sender_name': _get_display_name(sender),
        'sender_role': sender.role if sender else None,
        'sender_initials': _get_initials(sender),
        'message_type': msg.message_type or 'text',
        'content': msg.content,
        'timestamp': msg.timestamp.isoformat() if msg.timestamp else None,
        'status': msg.message_status or 'sent',
        'is_read': msg.is_read,
        'has_file': bool(msg.encrypted_file_path or msg.encrypted_file_blob),
        'reply_to_message_id': msg.reply_to_message_id,
    }
    # Profile picture URL
    try:
        data['sender_avatar'] = url_for('profile_picture', user_id=msg.sender_id, _external=False)
    except Exception:
        data['sender_avatar'] = None

    # Reply preview
    if include_reply and msg.reply_to_message_id:
        parent = db.session.get(Communication, msg.reply_to_message_id)
        if parent:
            data['reply_preview'] = _reply_preview(parent)
            data['reply_sender_name'] = _get_display_name(parent.sender)
        else:
            data['reply_preview'] = 'Deleted message'
            data['reply_sender_name'] = ''
    return data


# ═══════════════════════════════════════════════════════════════════════════
#  REST ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@messaging_bp.route('/messages/<int:appointment_id>', methods=['GET'])
@login_required
def get_messages(appointment_id):
    """Fetch messages for an appointment with cursor-based pagination."""
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment or not _verify_access(appointment, current_user):
        return jsonify({'success': False, 'error': 'access_denied'}), 403

    before_id = request.args.get('before_id', type=int)
    limit = min(request.args.get('limit', 50, type=int), 200)
    search_q = request.args.get('q', '').strip()

    query = Communication.query.filter_by(appointment_id=appointment_id)
    if before_id:
        query = query.filter(Communication.id < before_id)
    query = query.order_by(Communication.id.desc()).limit(limit)
    messages = list(reversed(query.all()))

    # Optional text search filter
    if search_q:
        search_lower = search_q.lower()
        messages = [m for m in messages if m.content and search_lower in m.content.lower()]

    return jsonify({
        'success': True,
        'appointment_id': appointment_id,
        'messages': [_serialize(m) for m in messages],
        'has_more': len(messages) == limit,
    })


@messaging_bp.route('/send', methods=['POST'])
@login_required
def send_message_http():
    """HTTP fallback for sending text messages when Socket.IO is unavailable."""
    data = request.get_json(silent=True) or {}
    appointment_id = data.get('appointment_id')
    content = (data.get('content') or '').strip()
    msg_type = data.get('message_type', 'text')
    client_msg_id = data.get('client_msg_id')
    reply_to = data.get('reply_to_message_id')

    if not appointment_id or not content:
        return jsonify({'success': False, 'error': 'appointment_id and content required'}), 400
    if len(content) > MAX_MESSAGE_LENGTH:
        return jsonify({'success': False, 'error': 'Message too long'}), 400

    appointment = db.session.get(Appointment, int(appointment_id))
    if not appointment or not _verify_access(appointment, current_user):
        return jsonify({'success': False, 'error': 'access_denied'}), 403
    if _check_payment(appointment.id, current_user):
        return jsonify({'success': False, 'error': 'payment_required'}), 402

    if not _rate_limit_check(current_user.id, 'msg_send', RATE_LIMIT_MESSAGES, 60):
        return jsonify({'success': False, 'error': 'rate_limited'}), 429

    # Idempotency check
    if client_msg_id:
        cached = _idempotency_get(current_user.id, client_msg_id)
        if cached:
            return jsonify({'success': True, 'message': cached})

    comm = Communication(
        appointment_id=appointment.id,
        sender_id=current_user.id,
        message_type=msg_type,
        content=content,
        timestamp=datetime.now(timezone.utc),
        is_read=False,
        message_status='sent',
        reply_to_message_id=reply_to,
    )
    db.session.add(comm)
    db.session.commit()

    msg_data = _serialize(comm)

    if client_msg_id:
        _idempotency_set(current_user.id, client_msg_id, msg_data)

    # Broadcast via Socket.IO
    if _socketio:
        _socketio.emit('new_message', msg_data, room=_room(appointment.id))

    return jsonify({'success': True, 'message': msg_data})


@messaging_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Upload file / voice-note / image attachment."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    f = request.files['file']
    appointment_id = request.form.get('appointment_id', type=int)
    msg_type = request.form.get('message_type', 'document')
    client_msg_id = request.form.get('client_msg_id')
    caption = (request.form.get('caption') or '').strip()
    reply_to = request.form.get('reply_to_message_id', type=int)

    if not appointment_id:
        return jsonify({'success': False, 'error': 'appointment_id required'}), 400

    appointment = db.session.get(Appointment, appointment_id)
    if not appointment or not _verify_access(appointment, current_user):
        return jsonify({'success': False, 'error': 'access_denied'}), 403
    if _check_payment(appointment.id, current_user):
        return jsonify({'success': False, 'error': 'payment_required'}), 402

    # Validate file
    file_bytes = f.read()
    if len(file_bytes) > MAX_FILE_SIZE:
        return jsonify({'success': False, 'error': f'File exceeds {MAX_FILE_SIZE // (1024*1024)}MB limit'}), 400
    if len(file_bytes) == 0:
        return jsonify({'success': False, 'error': 'Empty file'}), 400

    mime = f.content_type or 'application/octet-stream'
    # Strip codec parameters (e.g. "audio/webm;codecs=opus" → "audio/webm")
    base_mime = mime.split(';')[0].strip()
    if base_mime not in ALLOWED_MIME_TYPES:
        return jsonify({'success': False, 'error': 'File type not allowed'}), 400

    # Idempotency
    if client_msg_id:
        cached = _idempotency_get(current_user.id, client_msg_id)
        if cached:
            return jsonify({'success': True, 'message': cached})

    # Encrypt and store as blob
    encrypted_blob = encrypt_file_bytes(file_bytes)

    comm = Communication(
        appointment_id=appointment.id,
        sender_id=current_user.id,
        message_type=msg_type,
        content=caption or f.filename or msg_type,
        encrypted_file_blob=encrypted_blob,
        timestamp=datetime.now(timezone.utc),
        is_read=False,
        message_status='sent',
        reply_to_message_id=reply_to,
        sound_enabled=True,
    )
    db.session.add(comm)
    db.session.commit()

    msg_data = _serialize(comm)

    if client_msg_id:
        _idempotency_set(current_user.id, client_msg_id, msg_data)

    if _socketio:
        _socketio.emit('new_message', msg_data, room=_room(appointment.id))

    return jsonify({'success': True, 'message': msg_data})


@messaging_bp.route('/file/<int:message_id>', methods=['GET'])
@login_required
def download_file(message_id):
    """Download an encrypted file attachment."""
    # Check signed-url token first (allows unauthenticated download via link)
    token = request.args.get('token')
    uid = request.args.get('uid', type=int)
    if token and uid:
        if not _verify_signed_url(message_id, uid, token):
            abort(403)
    else:
        # Standard auth check
        comm = db.session.get(Communication, message_id)
        if not comm:
            abort(404)
        appointment = db.session.get(Appointment, comm.appointment_id)
        if not appointment or not _verify_access(appointment, current_user):
            abort(403)

    comm = db.session.get(Communication, message_id)
    if not comm:
        abort(404)

    # Decrypt blob
    if comm.encrypted_file_blob:
        decrypted = decrypt_file_bytes(comm.encrypted_file_blob)
        if not decrypted:
            abort(500)
        mime_map = {
            'image': 'image/jpeg', 'voice_note': 'audio/webm',
            'document': 'application/pdf',
        }
        mime = mime_map.get(comm.message_type, 'application/octet-stream')
        filename = comm.content or f'file_{message_id}'
        return send_file(BytesIO(decrypted), mimetype=mime, download_name=filename)

    # Fallback: file_path based
    if comm.file_path:
        full_path = os.path.join(current_app.root_path, comm.file_path)
        if os.path.exists(full_path):
            return send_file(full_path)

    abort(404)


@messaging_bp.route('/file/<int:message_id>/signed-url', methods=['GET'])
@login_required
def get_signed_url(message_id):
    """Generate a short-lived signed download URL."""
    comm = db.session.get(Communication, message_id)
    if not comm:
        return jsonify({'success': False, 'error': 'not_found'}), 404
    appointment = db.session.get(Appointment, comm.appointment_id)
    if not appointment or not _verify_access(appointment, current_user):
        return jsonify({'success': False, 'error': 'access_denied'}), 403

    token = _sign_url(message_id, current_user.id)
    dl_url = url_for('messaging.download_file', message_id=message_id,
                      token=token, uid=current_user.id, _external=True)
    return jsonify({'success': True, 'url': dl_url, 'expires_in': SIGNED_URL_TTL})


@messaging_bp.route('/status', methods=['POST'])
@login_required
def update_status():
    """Bulk update message statuses (delivered / read). Status only advances."""
    data = request.get_json(silent=True) or {}
    message_ids = data.get('message_ids', [])
    new_status = data.get('status', '')

    if new_status not in ('delivered', 'read'):
        return jsonify({'success': False, 'error': 'Invalid status'}), 400
    if not message_ids or len(message_ids) > 500:
        return jsonify({'success': False, 'error': 'Provide 1-500 message_ids'}), 400

    status_rank = {'sent': 0, 'delivered': 1, 'read': 2}
    new_rank = status_rank.get(new_status, 0)
    updated = []

    messages = Communication.query.filter(
        Communication.id.in_(message_ids),
        Communication.sender_id != current_user.id  # only recipient can advance
    ).all()

    for msg in messages:
        old_rank = status_rank.get(msg.message_status, 0)
        if new_rank > old_rank:
            msg.message_status = new_status
            if new_status == 'read':
                msg.is_read = True
            updated.append(msg.id)

    if updated:
        db.session.commit()
        # Broadcast status change
        if _socketio and messages:
            appointment_id = messages[0].appointment_id
            _socketio.emit('message_status_update', {
                'message_ids': updated,
                'status': new_status,
                'updated_by': current_user.id
            }, room=_room(appointment_id))

    return jsonify({'success': True, 'updated': updated})


@messaging_bp.route('/read/<int:appointment_id>', methods=['POST'])
@login_required
def mark_all_read(appointment_id):
    """Mark all unread messages in an appointment as read."""
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment or not _verify_access(appointment, current_user):
        return jsonify({'success': False, 'error': 'access_denied'}), 403

    unread = Communication.query.filter(
        Communication.appointment_id == appointment_id,
        Communication.sender_id != current_user.id,
        Communication.is_read == False
    ).all()

    ids = []
    for msg in unread:
        msg.is_read = True
        msg.message_status = 'read'
        ids.append(msg.id)

    if ids:
        db.session.commit()
        if _socketio:
            _socketio.emit('message_status_update', {
                'message_ids': ids,
                'status': 'read',
                'updated_by': current_user.id
            }, room=_room(appointment_id))

    return jsonify({'success': True, 'count': len(ids)})


@messaging_bp.route('/unread-counts', methods=['GET'])
@login_required
def unread_counts():
    """Get unread message counts per appointment for current user."""
    from sqlalchemy import func as sqlfunc
    rows = db.session.query(
        Communication.appointment_id,
        sqlfunc.count(Communication.id)
    ).filter(
        Communication.sender_id != current_user.id,
        Communication.is_read == False
    ).group_by(Communication.appointment_id).all()

    # Filter to only appointments the user has access to
    if current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        appt_ids = {a.id for a in Appointment.query.filter_by(doctor_id=doctor.id).all()} if doctor else set()
    elif current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        appt_ids = {a.id for a in Appointment.query.filter_by(patient_id=patient.id).all()} if patient else set()
    else:
        appt_ids = None  # admin sees all

    counts = {}
    for appt_id, count in rows:
        if appt_ids is None or appt_id in appt_ids:
            counts[str(appt_id)] = count

    return jsonify(counts)


@messaging_bp.route('/presence/<int:appointment_id>', methods=['GET'])
@login_required
def get_presence(appointment_id):
    """Check if the other party in an appointment is online."""
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment or not _verify_access(appointment, current_user):
        return jsonify({'success': False, 'error': 'access_denied'}), 403

    # Determine the other user
    if current_user.role == 'doctor':
        patient = db.session.get(Patient, appointment.patient_id)
        other_id = patient.user_id if patient else None
    elif current_user.role == 'patient':
        doctor = db.session.get(Doctor, appointment.doctor_id)
        other_id = doctor.user_id if doctor else None
    else:
        other_id = None

    online = _is_online(other_id) if other_id else False
    return jsonify({'success': True, 'online': online, 'user_id': other_id})


# ═══════════════════════════════════════════════════════════════════════════
#  SOCKET.IO HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

def _register_socket_handlers(socketio):

    @socketio.on('msg:join')
    def on_msg_join(data):
        if not current_user.is_authenticated:
            return
        data = data if isinstance(data, dict) else {}
        appointment_id = data.get('appointment_id')
        if not appointment_id:
            emit('msg:error', {'error': 'appointment_id required'})
            return

        appointment = db.session.get(Appointment, int(appointment_id))
        if not appointment or not _verify_access(appointment, current_user):
            emit('msg:error', {'error': 'access_denied'})
            return

        room = _room(appointment_id)
        join_room(room)
        emit('msg:joined', {'appointment_id': appointment_id, 'room': room})

        # Auto-deliver unread messages from other party
        undelivered = Communication.query.filter(
            Communication.appointment_id == int(appointment_id),
            Communication.sender_id != current_user.id,
            Communication.message_status == 'sent'
        ).all()
        delivered_ids = []
        for msg in undelivered:
            msg.message_status = 'delivered'
            delivered_ids.append(msg.id)
        if delivered_ids:
            db.session.commit()
            emit('message_status_update', {
                'message_ids': delivered_ids,
                'status': 'delivered',
                'updated_by': current_user.id
            }, room=room)

        # Notify others that user joined
        emit('msg:user_joined', {
            'user_id': current_user.id,
            'user_name': _get_display_name(current_user),
            'role': current_user.role,
            'online': True
        }, room=room, include_self=False)

    @socketio.on('msg:leave')
    def on_msg_leave(data):
        if not current_user.is_authenticated:
            return
        data = data if isinstance(data, dict) else {}
        appointment_id = data.get('appointment_id')
        if not appointment_id:
            return
        room = _room(appointment_id)
        leave_room(room)
        emit('msg:user_left', {
            'user_id': current_user.id,
            'user_name': _get_display_name(current_user),
            'role': current_user.role
        }, room=room, include_self=False)

    @socketio.on('msg:send')
    def on_msg_send(data):
        """Primary real-time message send path."""
        if not current_user.is_authenticated:
            emit('msg:error', {'error': 'auth_required'})
            return
        data = data if isinstance(data, dict) else {}
        appointment_id = data.get('appointment_id')
        content = (data.get('content') or '').strip()
        msg_type = data.get('message_type', 'text')
        client_msg_id = data.get('client_msg_id')
        reply_to = data.get('reply_to_message_id')

        if not appointment_id:
            emit('msg:error', {'error': 'appointment_id required', 'client_msg_id': client_msg_id})
            return
        if not content:
            emit('msg:error', {'error': 'content required', 'client_msg_id': client_msg_id})
            return
        if len(content) > MAX_MESSAGE_LENGTH:
            emit('msg:error', {'error': 'message_too_long', 'client_msg_id': client_msg_id})
            return

        appointment = db.session.get(Appointment, int(appointment_id))
        if not appointment or not _verify_access(appointment, current_user):
            emit('msg:error', {'error': 'access_denied', 'client_msg_id': client_msg_id})
            return
        if _check_payment(appointment.id, current_user):
            emit('msg:error', {'error': 'payment_required', 'client_msg_id': client_msg_id})
            return

        if not _rate_limit_check(current_user.id, 'msg_send', RATE_LIMIT_MESSAGES, 60):
            emit('msg:error', {'error': 'rate_limited', 'client_msg_id': client_msg_id})
            return

        # Idempotency
        if client_msg_id:
            cached = _idempotency_get(current_user.id, client_msg_id)
            if cached:
                emit('msg:ack', {**cached, 'client_msg_id': client_msg_id})
                return

        comm = Communication(
            appointment_id=appointment.id,
            sender_id=current_user.id,
            message_type=msg_type,
            content=content,
            timestamp=datetime.now(timezone.utc),
            is_read=False,
            message_status='sent',
            reply_to_message_id=reply_to,
        )
        db.session.add(comm)
        db.session.commit()

        msg_data = _serialize(comm)

        if client_msg_id:
            _idempotency_set(current_user.id, client_msg_id, msg_data)

        # Ack to sender
        emit('msg:ack', {**msg_data, 'client_msg_id': client_msg_id})

        # Broadcast to room (skip sender)
        room = _room(appointment.id)
        emit('new_message', msg_data, room=room, include_self=False)

    @socketio.on('msg:read')
    def on_msg_read(data):
        """Mark messages as read in real-time."""
        if not current_user.is_authenticated:
            return
        data = data if isinstance(data, dict) else {}
        appointment_id = data.get('appointment_id')
        message_ids = data.get('message_ids', [])

        if not appointment_id or not message_ids:
            return

        messages = Communication.query.filter(
            Communication.id.in_(message_ids),
            Communication.appointment_id == int(appointment_id),
            Communication.sender_id != current_user.id
        ).all()

        updated_ids = []
        for msg in messages:
            if msg.message_status != 'read':
                msg.message_status = 'read'
                msg.is_read = True
                updated_ids.append(msg.id)

        if updated_ids:
            db.session.commit()
            emit('message_status_update', {
                'message_ids': updated_ids,
                'status': 'read',
                'updated_by': current_user.id
            }, room=_room(appointment_id))

    @socketio.on('msg:typing')
    def on_msg_typing(data):
        if not current_user.is_authenticated:
            return
        data = data if isinstance(data, dict) else {}
        appointment_id = data.get('appointment_id')
        if not appointment_id:
            return
        emit('msg:typing', {
            'user_id': current_user.id,
            'user_name': _get_display_name(current_user),
            'appointment_id': appointment_id
        }, room=_room(appointment_id), include_self=False)

    @socketio.on('msg:stop_typing')
    def on_msg_stop_typing(data):
        if not current_user.is_authenticated:
            return
        data = data if isinstance(data, dict) else {}
        appointment_id = data.get('appointment_id')
        if not appointment_id:
            return
        emit('msg:stop_typing', {
            'user_id': current_user.id,
            'appointment_id': appointment_id
        }, room=_room(appointment_id), include_self=False)

    @socketio.on('msg:recording')
    def on_msg_recording(data):
        """Broadcast voice recording status indicator to appointment room."""
        if not current_user.is_authenticated:
            return
        data = data if isinstance(data, dict) else {}
        appointment_id = data.get('appointment_id')
        recording = data.get('recording', False)
        if not appointment_id:
            return
        emit('msg:recording', {
            'user_id': current_user.id,
            'user_name': _get_display_name(current_user),
            'recording': recording,
            'appointment_id': appointment_id
        }, room=_room(appointment_id), include_self=False)

    @socketio.on('msg:prescription')
    def on_msg_prescription(data):
        """Send a prescription as a special message in the chat."""
        if not current_user.is_authenticated:
            emit('msg:error', {'error': 'auth_required'})
            return
        if current_user.role != 'doctor':
            emit('msg:error', {'error': 'only_doctors_can_prescribe'})
            return

        data = data if isinstance(data, dict) else {}
        appointment_id = data.get('appointment_id')
        prescription_id = data.get('prescription_id')

        if not appointment_id or not prescription_id:
            emit('msg:error', {'error': 'appointment_id and prescription_id required'})
            return

        appointment = db.session.get(Appointment, int(appointment_id))
        if not appointment or not _verify_access(appointment, current_user):
            emit('msg:error', {'error': 'access_denied'})
            return

        from models import Prescription
        prescription = db.session.get(Prescription, int(prescription_id))
        if not prescription or prescription.appointment_id != appointment.id:
            emit('msg:error', {'error': 'prescription_not_found'})
            return

        import json
        content = json.dumps({
            'text': f'Prescription: {prescription.medication}',
            'prescription_id': prescription.id,
            'medication': prescription.medication,
            'dosage': prescription.dosage,
            'instructions': prescription.instructions or '',
        })

        comm = Communication(
            appointment_id=appointment.id,
            sender_id=current_user.id,
            message_type='prescription',
            content=content,
            timestamp=datetime.now(timezone.utc),
            is_read=False,
            message_status='sent',
        )
        db.session.add(comm)
        db.session.commit()

        msg_data = _serialize(comm)

        emit('msg:ack', msg_data)
        room = _room(appointment.id)
        emit('new_message', msg_data, room=room, include_self=False)
