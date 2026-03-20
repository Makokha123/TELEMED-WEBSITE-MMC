import os
import warnings

# Select async backend early so monkey patching happens before other imports.
# Default to threading for quieter startup logs unless ASYNC_MODE explicitly requests eventlet/gevent.
preferred_async = (os.getenv('ASYNC_MODE') or 'threading').strip().lower()
debug_mode = os.getenv('ENVIRONMENT', '') == 'development' or os.getenv('FLASK_DEBUG', '') == '1'
detected_async = None

if preferred_async not in ('eventlet', 'gevent', 'threading'):
    preferred_async = 'threading'

if preferred_async == 'eventlet':
    try:
        warnings.filterwarnings('ignore', category=DeprecationWarning, module=r'.*eventlet.*')
        import eventlet
        eventlet.monkey_patch()
        detected_async = 'eventlet'
    except Exception as e:
        if debug_mode:
            print(f"Eventlet unavailable ({e}); falling back to gevent")
        preferred_async = 'gevent'

if detected_async is None and preferred_async == 'gevent':
    try:
        from gevent import monkey as gevent_monkey
        gevent_monkey.patch_all(subprocess=False)
        detected_async = 'gevent'
    except Exception as e:
        if debug_mode:
            print(f"Gevent unavailable ({e}); falling back to threading")
        detected_async = 'threading'

if detected_async is None:
    detected_async = 'threading'

if debug_mode:
    print(f"Socket.IO async mode selected: {detected_async}")

import time
import logging
from flask_socketio import SocketIO, emit, join_room, leave_room
import gc
from flask import Flask, g, render_template, request, jsonify, redirect, url_for, flash, session
from flask import send_file, abort
from datetime import datetime, timedelta, timezone, date
import urllib
import math
import secrets
import string
import json
import hmac
import hashlib
from io import BytesIO
from email.utils import parseaddr

from authlib.integrations.flask_client import OAuth
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import aliased, joinedload
from sqlalchemy import QueuePool, func, distinct
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import inspect, text
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.utils import secure_filename
from uuid import uuid4
from PIL import Image
from flask_migrate import Migrate
import psutil

# Use East Africa Time (GMT+03:00) across the app
EAT_TZ = timezone(timedelta(hours=3))


def timeago(dt):
    if not dt:
        return 'N/A'
    now = datetime.now(timezone.utc)
    diff = now - dt if now > dt else dt - now
    seconds = diff.total_seconds()
    if seconds < 60:
        return f'{int(seconds)} seconds ago'
    if seconds < 3600:
        return f'{int(seconds // 60)} minutes ago'
    if seconds < 86400:
        return f'{int(seconds // 3600)} hours ago'
    if seconds < 604800:
        return f'{int(seconds // 86400)} days ago'
    return dt.strftime('%b %d, %Y')


try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


app = Flask(__name__)

cors_origins = os.getenv('SOCKETIO_CORS_ALLOWED_ORIGINS', '*')
if cors_origins and cors_origins.strip() != '*':
    cors_origins = [origin.strip() for origin in cors_origins.split(',') if origin.strip()]

socketio = SocketIO(
    app,
    cors_allowed_origins=cors_origins,
    async_mode=detected_async,
    logger=debug_mode,
    engineio_logger=debug_mode,
    ping_timeout=int(os.getenv('SOCKETIO_PING_TIMEOUT', 60)),
    ping_interval=int(os.getenv('SOCKETIO_PING_INTERVAL', 25)),
    max_http_buffer_size=int(float(os.getenv('SOCKETIO_MAX_HTTP_BUFFER_SIZE', 1e8))),
    manage_session=False,
    message_queue=os.getenv('REDIS_URL') or os.getenv('CELERY_BROKER_URL') or None,
)

SOCKETIO_AVAILABLE = True

# Import models (after attempting to load .env so ENCRYPTION_KEY can be read)
from models import (
    CallSession, Communication, PatientVital, Payment, Prescription, Report,
    PrescriptionAudit, Notification, HealthTip,
    SocialAccount, db, User, Patient, Doctor, Appointment, AuditLog, 
    Testimonial, MedicalRecord, _hash_value, encrypt_file_bytes, decrypt_file_bytes,
    CallHistory, CallQualityMetrics, UserPresence,
    EmailOTPChallenge, Partner, ConsultationRoom,
    SiteContent, PushSubscription, ConsultationRecording,
    SupportConversation, SupportMessage
)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from config import Config
try:
    from pywebpush import webpush, WebPushException
except ImportError:
    webpush = None
    WebPushException = Exception

try:
    import resend
except ImportError:
    resend = None

import click
import json as _json
import base64 as _base64
from pathlib import Path

# Initialize serializer for password reset tokens
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production-12345'))

# Global dictionary to track online users for Socket.IO presence
user_sockets = {}
user_last_seen = {}
active_calls = {}
call_rooms = {}  # Track call rooms: {call_id: {'caller': user_id, 'callee': user_id, 'appointment_id': apt_id}}
incoming_call_notifications = {}  # Track incoming calls waiting for answer: {user_id: call_info}
# Push subscriptions (in-memory). Persisted to `push_subscriptions.json` file in app root (best-effort)
push_subscriptions = {}
_PUSH_SUB_FILE = Path(app.root_path) / 'push_subscriptions.json'
# Simple in-memory rate limiter for messages: {user_id: [timestamp,...]}
message_rate = {}
# Generic per-user rate limiter for socket events (fallback when Redis unavailable)
rate_limits = {}
# Idempotency cache for client-supplied message IDs (fallback when Redis unavailable)
idempotency_cache = {}
metrics_cache = {}
room_memberships = {}
_redis_client = None


def _get_redis_client():
    """Return a Redis client if REDIS_URL is configured and reachable."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        redis_url = os.getenv('REDIS_URL') or os.getenv('SOCKETIO_REDIS_URL') or os.getenv('CELERY_BROKER_URL')
        if not redis_url or not str(redis_url).startswith('redis'):
            return None
        import redis  # local import to avoid hard dependency at import time
        client = redis.from_url(redis_url, decode_responses=True)
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception:
        _redis_client = None
        return None


def _redis_set_json(key, value, ttl_seconds=3600):
    try:
        client = _get_redis_client()
        if not client:
            return False
        payload = json.dumps(value)
        client.setex(key, int(ttl_seconds), payload)
        return True
    except Exception:
        return False


def _redis_get_json(key):
    try:
        client = _get_redis_client()
        if not client:
            return None
        raw = client.get(key)
        if not raw:
            return None
        return json.loads(raw)
    except Exception:
        return None


def _rate_limit(user_id, key, limit, window_seconds):
    """Return True if allowed, False if rate limited."""
    try:
        if not user_id:
            return True
        now_ts = time.time()
        client = _get_redis_client()
        if client:
            bucket_key = f'rl:{key}:{user_id}:{int(now_ts // window_seconds)}'
            count = client.incr(bucket_key)
            client.expire(bucket_key, int(window_seconds) + 2)
            return count <= limit
        # fallback: in-memory sliding window
        bucket = rate_limits.get((user_id, key), [])
        bucket = [t for t in bucket if now_ts - t < window_seconds]
        if len(bucket) >= limit:
            rate_limits[(user_id, key)] = bucket
            return False
        bucket.append(now_ts)
        rate_limits[(user_id, key)] = bucket
        return True
    except Exception:
        return True


def _idempotency_get(user_id, client_id):
    if not user_id or not client_id:
        return None
    key = f'idempo:{user_id}:{client_id}'
    cached = _redis_get_json(key)
    if cached:
        return cached
    return idempotency_cache.get(key)


def _idempotency_set(user_id, client_id, value, ttl_seconds=600):
    if not user_id or not client_id:
        return
    key = f'idempo:{user_id}:{client_id}'
    idempotency_cache[key] = value
    # best-effort: set redis
    _redis_set_json(key, value, ttl_seconds=ttl_seconds)


def _normalize_sid_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return [v for v in value if v]
    return [value]


def _user_sockets_key(user_id):
    return f"user_sockets:{user_id}"


def _get_user_sockets(user_id):
    try:
        if not user_id:
            return []
        cached = user_sockets.get(user_id)
        if cached:
            return _normalize_sid_list(cached)
        redis_val = _redis_get_json(_user_sockets_key(user_id))
        if redis_val:
            user_sockets[user_id] = _normalize_sid_list(redis_val)
            return _normalize_sid_list(redis_val)
        return []
    except Exception:
        return []


def _set_user_sockets(user_id, sids, ttl_seconds=3600):
    try:
        if not user_id:
            return
        sids = _normalize_sid_list(sids)
        if not sids:
            user_sockets.pop(user_id, None)
        else:
            user_sockets[user_id] = sids
        # best-effort: store in Redis with TTL
        client = _get_redis_client()
        if client:
            if sids:
                _redis_set_json(_user_sockets_key(user_id), sids, ttl_seconds=ttl_seconds)
                try:
                    client.sadd('online_users', str(user_id))
                    client.expire('online_users', 3600)
                except Exception:
                    pass
            else:
                try:
                    client.delete(_user_sockets_key(user_id))
                    client.srem('online_users', str(user_id))
                except Exception:
                    pass
    except Exception:
        pass


def _add_user_socket(user_id, sid):
    try:
        if not user_id or not sid:
            return
        sids = _get_user_sockets(user_id)
        if sid not in sids:
            sids.append(sid)
        _set_user_sockets(user_id, sids)
    except Exception:
        pass


def _remove_user_socket(user_id, sid):
    try:
        if not user_id or not sid:
            return
        sids = _get_user_sockets(user_id)
        if sid in sids:
            sids.remove(sid)
        _set_user_sockets(user_id, sids)
    except Exception:
        pass


def _incoming_call_key(user_id):
    return f"incoming_call:{user_id}"


def _incoming_call_set(user_id, call_info, ttl_seconds=180):
    try:
        if not user_id:
            return
        incoming_call_notifications[user_id] = call_info
        _redis_set_json(_incoming_call_key(user_id), call_info, ttl_seconds=ttl_seconds)
    except Exception:
        pass


def _incoming_call_get(user_id):
    try:
        if not user_id:
            return None
        cached = incoming_call_notifications.get(user_id)
        if cached:
            return cached
        redis_val = _redis_get_json(_incoming_call_key(user_id))
        if redis_val:
            incoming_call_notifications[user_id] = redis_val
            return redis_val
        return None
    except Exception:
        return None


def _incoming_call_pop(user_id):
    try:
        if not user_id:
            return
        incoming_call_notifications.pop(user_id, None)
        client = _get_redis_client()
        if client:
            try:
                client.delete(_incoming_call_key(user_id))
            except Exception:
                pass
    except Exception:
        pass


def _metric_incr(name, delta=1):
    try:
        key = f"metrics:{name}"
        client = _get_redis_client()
        if client:
            try:
                return client.incrby(key, int(delta))
            except Exception:
                pass
        metrics_cache[name] = metrics_cache.get(name, 0) + int(delta)
        return metrics_cache[name]
    except Exception:
        return None


def _metric_set(name, value, ttl_seconds=3600):
    try:
        key = f"metrics:{name}"
        client = _get_redis_client()
        if client:
            try:
                client.set(key, int(value), ex=ttl_seconds)
            except Exception:
                pass
        metrics_cache[name] = int(value)
    except Exception:
        pass


def _room_member_add(room, user_id, ttl_seconds=3600):
    if not room or not user_id:
        return None
    try:
        client = _get_redis_client()
        if client:
            key = f"room_members:{room}"
            client.sadd(key, str(user_id))
            client.expire(key, ttl_seconds)
            return client.scard(key)
    except Exception:
        pass
    try:
        members = room_memberships.get(room)
        if members is None:
            members = set()
            room_memberships[room] = members
        members.add(user_id)
        return len(members)
    except Exception:
        return None


def _room_member_remove(room, user_id):
    if not room or not user_id:
        return None
    try:
        client = _get_redis_client()
        if client:
            key = f"room_members:{room}"
            client.srem(key, str(user_id))
            return client.scard(key)
    except Exception:
        pass
    try:
        members = room_memberships.get(room)
        if members and user_id in members:
            members.remove(user_id)
        return len(members) if members else 0
    except Exception:
        return None


def _room_member_ids(room):
    if not room:
        return []
    try:
        client = _get_redis_client()
        if client:
            members = client.smembers(f"room_members:{room}") or []
            return _unique_user_ids(members)
    except Exception:
        pass
    try:
        members = room_memberships.get(room) or set()
        return _unique_user_ids(list(members))
    except Exception:
        return []


def _count_online_users():
    try:
        client = _get_redis_client()
        if client:
            try:
                return client.scard('online_users')
            except Exception:
                pass
        return len(user_sockets)
    except Exception:
        return len(user_sockets)


def _set_presence(user_id, online=True):
    """Persist lightweight presence info to Redis if available."""
    try:
        if not user_id:
            return
        payload = {
            'online': bool(online),
            'last_seen': now_eat().isoformat()
        }
        _redis_set_json(f'presence:{user_id}', payload, ttl_seconds=120)
    except Exception:
        pass


def _is_user_online(user_id):
    """Best-effort online check using in-memory sockets or Redis presence."""
    try:
        if not user_id:
            return False
        if _get_user_sockets(user_id):
            return True
        presence = _redis_get_json(f'presence:{user_id}')
        if presence:
            return bool(presence.get('online'))
        return False
    except Exception:
        return False


def now_eat():
    return datetime.now(EAT_TZ)

# Ensure database datetimes are treated as EAT if stored without tzinfo
def _coerce_eat(dt):
    if dt is None:
        return None
    if getattr(dt, 'tzinfo', None) is None:
        return dt.replace(tzinfo=EAT_TZ)
    return dt


def _store_active_call(call_info):
    if not isinstance(call_info, dict):
        return
    call_id = call_info.get('id') or call_info.get('call_id')
    appointment_id = call_info.get('appointment_id')
    if call_id:
        active_calls[call_id] = call_info
        _redis_set_json(f'active_call:{call_id}', call_info, ttl_seconds=7200)
    if appointment_id:
        active_calls[appointment_id] = call_info
        _redis_set_json(f'active_call:appointment:{appointment_id}', call_info, ttl_seconds=7200)


def _clear_active_call(call_info):
    if not isinstance(call_info, dict):
        return
    keys = [call_info.get('id'), call_info.get('call_id'), call_info.get('appointment_id')]
    for key in keys:
        if not key:
            continue
        try:
            active_calls.pop(key, None)
        except Exception:
            pass


def _is_user_busy(user_id):
    try:
        target = int(user_id)
    except Exception:
        return False
    for call in active_calls.values():
        if not isinstance(call, dict):
            continue
        participants = _call_participant_ids(call, include_observers=False)
        statuses = {'ringing', 'accepted', 'connected', 'ongoing'}
        if call.get('status') in statuses and any(p == target for p in participants):
            return True
    return False


def _get_call_room_name(call_type, appointment_id=None, call_id=None):
    base = 'video_call' if call_type == 'video' else 'voice_call'
    suffix = appointment_id or call_id
    return f'{base}_{suffix}' if suffix else f'{base}_{uuid4().hex[:10]}'


def _get_call_media_topology():
    return (os.getenv('CALL_MEDIA_TOPOLOGY') or 'sfu-ready').strip().lower()


def _get_call_sfu_server():
    return (os.getenv('CALL_SFU_SERVER') or 'internal-room-router').strip()


def _unique_user_ids(values):
    unique_ids = []
    for value in values or []:
        try:
            parsed = int(value)
        except Exception:
            continue
        if parsed not in unique_ids:
            unique_ids.append(parsed)
    return unique_ids


def _serialize_call_participant(user_id, mode='participant', status='invited', joined=False):
    user = db.session.get(User, int(user_id)) if user_id else None
    return {
        'user_id': int(user_id),
        'role': getattr(user, 'role', None),
        'name': safe_display_name(user) if user else 'Unknown',
        'profile_picture': get_user_profile_picture_url(user) if user else None,
        'mode': mode,
        'status': status,
        'joined': bool(joined),
        'online': _is_user_online(user_id)
    }


def _build_call_participants(appointment, caller_id, callee_id=None, participant_ids=None, observer_ids=None):
    appointment_user_ids = []
    if appointment:
        try:
            if appointment.patient and appointment.patient.user_id:
                appointment_user_ids.append(int(appointment.patient.user_id))
        except Exception:
            pass
        try:
            if appointment.doctor and appointment.doctor.user_id:
                appointment_user_ids.append(int(appointment.doctor.user_id))
        except Exception:
            pass

    requested_ids = _unique_user_ids([caller_id, callee_id] + list(participant_ids or []) + appointment_user_ids)
    observer_set = set(_unique_user_ids(observer_ids or []))
    participants = []

    for user_id in requested_ids:
        mode = 'observer' if user_id in observer_set else 'participant'
        is_caller = int(user_id) == int(caller_id)
        participants.append(_serialize_call_participant(
            user_id,
            mode=mode,
            status='connected' if is_caller else 'invited',
            joined=is_caller,
        ))

    return participants


def _call_participant_ids(call_info=None, include_observers=True, connected_only=False):
    participants = []
    if not isinstance(call_info, dict):
        return participants

    for participant in call_info.get('participants') or []:
        if not isinstance(participant, dict):
            continue
        if not include_observers and participant.get('mode') == 'observer':
            continue
        if connected_only and not participant.get('joined'):
            continue
        try:
            user_id = int(participant.get('user_id'))
        except Exception:
            continue
        if user_id not in participants:
            participants.append(user_id)

    if participants:
        return participants

    for key in ('caller', 'caller_id', 'callee', 'callee_id'):
        value = call_info.get(key)
        if value is None:
            continue
        try:
            value = int(value)
        except Exception:
            continue
        if value not in participants:
            participants.append(value)
    return participants


def _is_call_participant(call_info, user_id, include_observers=False):
    try:
        target = int(user_id)
    except Exception:
        return False
    return target in _call_participant_ids(call_info, include_observers=include_observers)


def _mark_call_participant(call_info, user_id, status=None, joined=None, mode=None):
    if not isinstance(call_info, dict):
        return False
    try:
        target = int(user_id)
    except Exception:
        return False

    updated = False
    participants = call_info.get('participants') or []
    for participant in participants:
        if not isinstance(participant, dict):
            continue
        try:
            participant_id = int(participant.get('user_id'))
        except Exception:
            continue
        if participant_id != target:
            continue
        if status is not None:
            participant['status'] = status
        if joined is not None:
            participant['joined'] = bool(joined)
        if mode is not None:
            participant['mode'] = mode
        participant['online'] = _is_user_online(target)
        updated = True
        break

    if not updated:
        participant = _serialize_call_participant(
            target,
            mode=mode or 'participant',
            status=status or 'connected',
            joined=bool(joined) if joined is not None else True,
        )
        participants.append(participant)
        updated = True

    call_info['participants'] = participants
    call_info['participant_ids'] = _call_participant_ids(call_info, include_observers=False)
    call_info['observer_ids'] = _call_participant_ids({
        'participants': participants
    }, include_observers=True)
    call_info['connected_participant_ids'] = _call_participant_ids(call_info, include_observers=True, connected_only=True)
    call_info['participants_count'] = len(_call_participant_ids(call_info, include_observers=False))
    call_info['observer_count'] = len([p for p in participants if p.get('mode') == 'observer'])
    return updated


def _serialize_active_call(call_info):
    if not isinstance(call_info, dict):
        return None
    started_at = call_info.get('started_at') or call_info.get('ringing_at')
    duration_seconds = None
    try:
        if started_at:
            duration_seconds = int((now_eat() - datetime.fromisoformat(started_at)).total_seconds())
    except Exception:
        duration_seconds = None

    return {
        'call_id': call_info.get('id') or call_info.get('call_id'),
        'appointment_id': call_info.get('appointment_id'),
        'call_type': call_info.get('call_type', 'video'),
        'status': call_info.get('status'),
        'caller_id': call_info.get('caller') or call_info.get('caller_id'),
        'callee_id': call_info.get('callee') or call_info.get('callee_id'),
        'caller_name': call_info.get('caller_name'),
        'callee_name': call_info.get('callee_name'),
        'started_at': started_at,
        'connected_at': call_info.get('connected_at'),
        'duration_seconds': duration_seconds,
        'participants': call_info.get('participants') or [],
        'participants_count': call_info.get('participants_count') or len(_call_participant_ids(call_info, include_observers=False)),
        'observer_count': call_info.get('observer_count') or len([p for p in call_info.get('participants') or [] if p.get('mode') == 'observer']),
        'room_id': call_info.get('room_id'),
        'media_topology': call_info.get('media_topology') or _get_call_media_topology(),
        'sfu_server': call_info.get('sfu_server') or _get_call_sfu_server(),
        'auto_record': bool(call_info.get('auto_record', True)),
        'recording_state': call_info.get('recording_state') or 'armed',
        'group_call': bool(call_info.get('group_call')),
        'observe_url': url_for('video_call', appointment_id=call_info.get('appointment_id'), observer='1') if call_info.get('appointment_id') and call_info.get('call_type', 'video') == 'video' else None,
    }


def _build_call_page_members(appointment, call_info=None, observe_mode=False):
    members_by_id = {}
    current_user_id = getattr(current_user, 'id', None)

    def _upsert_member(user_id, role=None, mode='participant', status='invited', joined=False, online=None):
        try:
            parsed_user_id = int(user_id)
        except Exception:
            return

        user = db.session.get(User, parsed_user_id)
        display_name = safe_display_name(user) if user else f'User {parsed_user_id}'
        profile_picture_url = get_user_profile_picture_url(user) if user else None
        normalized_role = role or getattr(user, 'role', None) or 'participant'
        subtitle = 'Silent observer' if mode == 'observer' else ('Care team member' if normalized_role == 'admin' else normalized_role.replace('_', ' ').title())

        existing = members_by_id.get(parsed_user_id, {})
        if existing.get('joined'):
            joined = True
        if existing.get('status') == 'connected' and status != 'connected':
            status = existing.get('status')
        if existing.get('mode') == 'observer' and mode != 'observer':
            mode = 'observer'

        members_by_id[parsed_user_id] = {
            'user_id': parsed_user_id,
            'display_name': display_name,
            'profile_picture_url': profile_picture_url,
            'role': normalized_role,
            'subtitle': subtitle,
            'mode': mode,
            'status': status,
            'joined': bool(joined),
            'online': _is_user_online(parsed_user_id) if online is None else bool(online),
            'is_current_user': parsed_user_id == current_user_id,
        }

    if isinstance(call_info, dict):
        for participant in call_info.get('participants') or []:
            if not isinstance(participant, dict):
                continue
            _upsert_member(
                participant.get('user_id'),
                role=participant.get('role'),
                mode=participant.get('mode') or 'participant',
                status=participant.get('status') or ('connected' if participant.get('joined') else 'invited'),
                joined=participant.get('joined'),
                online=participant.get('online'),
            )

    if appointment:
        try:
            if appointment.doctor and appointment.doctor.user_id:
                _upsert_member(
                    appointment.doctor.user_id,
                    role='doctor',
                    mode='participant',
                    status='connected' if int(appointment.doctor.user_id) == current_user_id and not observe_mode else 'invited',
                    joined=int(appointment.doctor.user_id) == current_user_id and not observe_mode,
                )
        except Exception:
            pass
        try:
            if appointment.patient and appointment.patient.user_id:
                _upsert_member(
                    appointment.patient.user_id,
                    role='patient',
                    mode='participant',
                    status='connected' if int(appointment.patient.user_id) == current_user_id and not observe_mode else 'invited',
                    joined=int(appointment.patient.user_id) == current_user_id and not observe_mode,
                )
        except Exception:
            pass

    if getattr(current_user, 'role', None) == 'admin':
        _upsert_member(
            current_user_id,
            role='admin',
            mode='observer' if observe_mode else 'participant',
            status='connected' if observe_mode else 'invited',
            joined=observe_mode,
            online=True,
        )

    def _member_sort_key(member):
        role_priority = {'doctor': 0, 'patient': 1, 'admin': 2}
        return (
            0 if member.get('is_current_user') else 1,
            0 if member.get('joined') else 1,
            role_priority.get(member.get('role'), 9),
            member.get('display_name') or ''
        )

    return sorted(members_by_id.values(), key=_member_sort_key)


def _resolve_call_room(appointment_id=None, call_id=None, call_type='video'):
    _, call_info = find_active_call(call_id=call_id, appointment_id=appointment_id)
    if call_info and call_info.get('room_id'):
        return call_info.get('room_id')
    if appointment_id:
        return f'{"video_call" if call_type == "video" else "voice_call"}_{appointment_id}'
    return _get_call_room_name(call_type, appointment_id=appointment_id, call_id=call_id)


def _emit_call_signal(event_name, payload, appointment_id=None, call_id=None, call_type='video', target_user_id=None):
    room_name = _resolve_call_room(appointment_id=appointment_id, call_id=call_id, call_type=call_type)
    if target_user_id:
        _emit_to_user(int(target_user_id), event_name, payload)
        return room_name
    emit(event_name, payload, room=room_name, skip_sid=request.sid)
    return room_name


def _get_public_media_bridge_config(call_info=None):
    topology = (call_info or {}).get('media_topology') or _get_call_media_topology()
    provider = (os.getenv('CALL_SFU_PROVIDER') or '').strip().lower() or None
    sfu_server = (call_info or {}).get('sfu_server') or _get_call_sfu_server()
    ws_url = (os.getenv('CALL_SFU_WS_URL') or '').strip() or None
    http_url = (os.getenv('CALL_SFU_HTTP_URL') or '').strip() or None
    room_prefix = (os.getenv('CALL_SFU_ROOM_PREFIX') or 'telemed').strip()
    supported = bool(provider and (ws_url or http_url))
    return {
        'topology': topology,
        'provider': provider,
        'server': sfu_server,
        'ws_url': ws_url,
        'http_url': http_url,
        'room_prefix': room_prefix,
        'supported': supported,
        'mesh_fallback': True,
    }


def _get_call_participant_mode(call_info, user_id, default_mode='participant'):
    try:
        target_user_id = int(user_id)
    except Exception:
        return default_mode
    for participant in (call_info or {}).get('participants') or []:
        if not isinstance(participant, dict):
            continue
        try:
            participant_user_id = int(participant.get('user_id'))
        except Exception:
            continue
        if participant_user_id == target_user_id:
            return participant.get('mode') or default_mode
    return default_mode


def _build_media_bridge_session(room_id, appointment_id=None, call_info=None, call_type='video', user=None):
    user = user or current_user
    if not user or not getattr(user, 'is_authenticated', False):
        return None

    public_config = _get_public_media_bridge_config(call_info)
    room_prefix = public_config.get('room_prefix') or 'telemed'
    room_name = f'{room_prefix}-{room_id}' if room_id else f'{room_prefix}-{uuid4().hex[:12]}'
    token_ttl_seconds = max(60, int(os.getenv('CALL_SFU_TOKEN_TTL_SECONDS', '900')))
    expires_at = now_eat() + timedelta(seconds=token_ttl_seconds)
    participant_mode = _get_call_participant_mode(call_info, getattr(user, 'id', None), default_mode='participant')
    can_publish = participant_mode != 'observer'
    identity = f'user-{int(user.id)}'
    payload = {
        'sub': identity,
        'user_id': int(user.id),
        'appointment_id': int(appointment_id) if appointment_id else None,
        'room_id': room_id,
        'room_name': room_name,
        'call_type': call_type,
        'role': getattr(user, 'role', None),
        'mode': participant_mode,
        'can_publish': can_publish,
        'topology': public_config.get('topology'),
        'provider': public_config.get('provider'),
        'exp': expires_at.isoformat(),
    }
    signed_token = s.dumps(payload, salt='call-media-bridge')
    return {
        'issued_at': now_eat().isoformat(),
        'expires_at': expires_at.isoformat(),
        'ttl_seconds': token_ttl_seconds,
        'room_name': room_name,
        'room_id': room_id,
        'participant_identity': identity,
        'participant_name': safe_display_name(user),
        'participant_role': getattr(user, 'role', None),
        'participant_mode': participant_mode,
        'auth_type': 'signed-session',
        'token': signed_token,
        'auth_header': os.getenv('CALL_SFU_TOKEN_HEADER', 'Authorization'),
        'auth_scheme': os.getenv('CALL_SFU_TOKEN_SCHEME', 'Bearer'),
        'permissions': {
            'publish': can_publish,
            'subscribe': True,
            'record': bool((call_info or {}).get('auto_record', True)),
        },
        'join_urls': {
            'ws': public_config.get('ws_url'),
            'http': public_config.get('http_url'),
        },
    }


def _socket_get_appointment(appointment_id, error_event='call_error', require_payment=False):
    try:
        if not appointment_id:
            emit(error_event, {'error': 'appointment_required'})
            return None
        appointment = db.session.get(Appointment, int(appointment_id))
        if not appointment:
            emit(error_event, {'error': 'appointment_not_found'})
            return None
        if not (verify_appointment_access(appointment, current_user) or getattr(current_user, 'role', None) == 'admin'):
            emit(error_event, {'error': 'access_denied'})
            return None
        if require_payment and getattr(current_user, 'role', None) == 'patient' and is_patient_payment_locked(appointment.id):
            _metric_incr('calls_payment_blocked', 1)
            _log_event('call_payment_blocked', user_id=getattr(current_user, 'id', None), appointment_id=appointment.id)
            emit(error_event, {'error': 'payment_required', 'appointment_id': appointment.id})
            return None
        return appointment
    except Exception:
        emit(error_event, {'error': 'appointment_lookup_failed'})
        return None


def _log_event(event, **fields):
    try:
        parts = [f"{k}={v}" for k, v in fields.items() if v is not None]
        app.logger.info("event=%s %s", event, " ".join(parts))
    except Exception:
        pass


import requests as requests_lib

def get_xirsys_turn_servers():
    """Fetch dynamic TURN credentials from XIRSYS API
    XIRSYS provides reliable, geo-optimized TURN servers with automatic credential rotation.
    Falls back to static env vars if API fails.
    
    API Docs: https://developer.xirsys.com/
    """
    # Allow disabling in dev or constrained environments
    if os.getenv('XIRSYS_DISABLED', '').lower() in ('1', 'true', 'yes'):
        app.logger.info('XIRSYS disabled via XIRSYS_DISABLED; using static config.')
        return None
    if debug_mode and os.getenv('XIRSYS_FORCE', '').lower() not in ('1', 'true', 'yes'):
        app.logger.info('Skipping XIRSYS TURN fetch in development; set XIRSYS_FORCE=1 to enable.')
        return None

    try:
        ident = os.getenv('XIRSYS_IDENT')
        secret = os.getenv('XIRSYS_SECRET')
        
        if not ident or not secret:
            return None
        
        api_url = os.getenv('XIRSYS_API_URL', 'https://api.xirsys.com/v3/signal/iceServers')
        
        # Call XIRSYS API to get TURN servers
        # Uses Basic Auth (ident:secret)
        response = requests_lib.get(
            api_url,
            auth=(ident, secret),
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # XIRSYS returns: { "v": {iceServers: [{...}]} }
            servers = data.get('v', {}).get('iceServers', [])
            
            if servers:
                app.logger.info(f'✓ XIRSYS TURN credentials loaded successfully ({len(servers)} servers)')
                return servers
    except Exception as e:
        app.logger.info(f'XIRSYS fetch unavailable: {e}. Falling back to static config.')
    
    return None


# ===== EMAIL SENDING FUNCTIONS (RESEND) =====
def _normalize_email_address(value):
    if value is None:
        return ''
    _, parsed = parseaddr(str(value))
    candidate = parsed or str(value)
    return candidate.strip().lower()


def _is_valid_email_address(value):
    value = _normalize_email_address(value)
    if not value or '@' not in value:
        return False
    local, _, domain = value.partition('@')
    return bool(local and domain and '.' in domain)


def _resolve_sender_email(*candidates):
    fallback_candidates = list(candidates) + [
        os.getenv('RESEND_FROM_EMAIL'),
        os.getenv('EMAIL_NOREPLY'),
        app.config.get('MAIL_DEFAULT_SENDER'),
        app.config.get('MAIL_USERNAME'),
        os.getenv('MAIL_USERNAME')
    ]
    for candidate in fallback_candidates:
        normalized = _normalize_email_address(candidate)
        if _is_valid_email_address(normalized):
            return normalized
    return None


def _prepare_email_attachments(attachments):
    prepared = []
    for item in attachments or []:
        if not isinstance(item, dict):
            continue
        filename = (item.get('filename') or 'attachment.bin').strip()
        content_type = (item.get('content_type') or item.get('type') or 'application/octet-stream').strip()
        data = item.get('data')
        if data is None and item.get('content'):
            try:
                data = _base64.b64decode(item.get('content'))
            except Exception:
                data = None
        if isinstance(data, str):
            data = data.encode('utf-8')
        if not isinstance(data, (bytes, bytearray)):
            continue
        prepared.append({
            'filename': filename,
            'content_type': content_type,
            'data': bytes(data),
        })
    return prepared


def _send_email_smtp(recipient_email, subject, html_content, from_email=None, attachments=None):
    sender_email = _resolve_sender_email(from_email)
    if not sender_email:
        return {'success': False, 'message': 'No valid sender email configured for SMTP fallback', 'email_id': None}

    mail_server = app.config.get('MAIL_SERVER')
    mail_username = app.config.get('MAIL_USERNAME')
    mail_password = app.config.get('MAIL_PASSWORD')
    if not mail_server or not mail_username or not mail_password:
        return {'success': False, 'message': 'SMTP fallback not configured', 'email_id': None}

    try:
        message = Message(
            subject=subject,
            recipients=[recipient_email],
            html=html_content,
            sender=sender_email
        )
        for attachment in _prepare_email_attachments(attachments):
            message.attach(
                attachment.get('filename') or 'attachment.bin',
                attachment.get('content_type') or 'application/octet-stream',
                attachment.get('data') or b''
            )
        mail.send(message)
        app.logger.info(f'✓ Email sent via SMTP fallback to {recipient_email}')
        return {'success': True, 'message': 'Email sent successfully via SMTP fallback', 'email_id': None}
    except Exception as smtp_error:
        app.logger.error(f'✗ SMTP fallback failed for {recipient_email}: {smtp_error}')
        return {'success': False, 'message': f'SMTP fallback failed: {smtp_error}', 'email_id': None}


def _otp_hash(email, otp_code):
    return hashlib.sha256(f'{_normalize_email_address(email)}:{otp_code}'.encode()).hexdigest()


def _generate_numeric_otp(length=6):
    length = max(4, min(int(length), 10))
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def _otp_settings():
    ttl_seconds = int(os.getenv('EMAIL_OTP_TTL_SECONDS', '600'))
    resend_seconds = int(os.getenv('EMAIL_OTP_RESEND_SECONDS', '60'))
    max_attempts = int(os.getenv('EMAIL_OTP_MAX_ATTEMPTS', '5'))
    return {
        'ttl_seconds': max(120, ttl_seconds),
        'resend_seconds': max(30, resend_seconds),
        'max_attempts': max(3, max_attempts),
    }

def _otp_now():
    """Return naive datetime in EAT for OTP storage/comparisons."""
    return now_eat().replace(tzinfo=None)

def _otp_normalize(dt):
    """Normalize stored OTP datetimes to naive EAT for safe comparisons."""
    if dt is None:
        return None
    if getattr(dt, 'tzinfo', None) is None:
        return dt
    return dt.astimezone(EAT_TZ).replace(tzinfo=None)


def _find_active_otp_challenge(email, purpose):
    email_hash = _hash_value(_normalize_email_address(email))
    now = _otp_now()
    return EmailOTPChallenge.query.filter(
        EmailOTPChallenge.email_hash == email_hash,
        EmailOTPChallenge.purpose == purpose,
        EmailOTPChallenge.consumed == False,
        EmailOTPChallenge.expires_at > now
    ).order_by(EmailOTPChallenge.created_at.desc()).first()


def _build_role_welcome_payload(user):
    role = (getattr(user, 'role', None) or '').strip().lower()
    if role == 'doctor':
        return {
            'headline': 'Welcome to the Clinical Team',
            'intro': 'Your doctor account is ready. You can now manage patients, consultations, and clinical notes securely.',
            'items': [
                'Review and complete your practitioner profile and license details.',
                'Set consultation availability and communication preferences.',
                'Use prescriptions, reports, and follow-up workflows from your dashboard.'
            ]
        }
    if role == 'admin':
        return {
            'headline': 'Welcome to the Administration Console',
            'intro': 'Your admin account is active with access to staff, patient operations, and platform oversight.',
            'items': [
                'Review security settings and enforce account governance.',
                'Manage staff onboarding, verification, and account lifecycle.',
                'Monitor operational dashboards and compliance indicators.'
            ]
        }
    if role in ('staff', 'worker'):
        return {
            'headline': 'Welcome to the Staff Workspace',
            'intro': 'Your staff account is active. You can now support patient and clinic operations securely.',
            'items': [
                'Review assigned duties and update your profile details.',
                'Use internal communication and workflow tools as assigned.',
                'Follow data handling and privacy guidelines for patient safety.'
            ]
        }
    return {
        'headline': 'Welcome to Makokha Medical Centre',
        'intro': 'Your patient account is ready. You can book appointments and access care securely online.',
        'items': [
            'Complete your health profile to personalize your care.',
            'Book video, voice, or messaging consultations with clinicians.',
            'Track appointments, records, prescriptions, and notifications.'
        ]
    }


class _RolePayload:
    """Template-safe wrapper to avoid dict.items method collisions in Jinja."""
    def __init__(self, data=None):
        self._data = data or {}
        self.headline = self._data.get('headline')
        self.intro = self._data.get('intro')
        self.items = list(self._data.get('items') or [])

    def get(self, key, default=None):
        return self._data.get(key, default)


def send_email_resend(recipient_email, subject, html_content, from_email=None, attachments=None):
    """Send email using Resend API
    
    Args:
        recipient_email: Email address to send to
        subject: Email subject
        html_content: HTML content of the email
        from_email: From email address (uses EMAIL_NOREPLY by default)
    
    Returns:
        dict with keys: {'success': bool, 'message': str, 'email_id': str or None}
    """
    try:
        recipient_email = _normalize_email_address(recipient_email)
        if not _is_valid_email_address(recipient_email):
            return {'success': False, 'message': 'Invalid recipient email address', 'email_id': None}

        from_email = _resolve_sender_email(from_email)
        if not from_email:
            app.logger.error('No valid sender email configured (RESEND_FROM_EMAIL/EMAIL_NOREPLY/MAIL_USERNAME)')
            return {'success': False, 'message': 'Email sender not configured', 'email_id': None}
        
        api_key = os.getenv('RESEND_API_KEY')
        if not api_key:
            app.logger.warning('RESEND_API_KEY not configured, trying SMTP fallback')
            return _send_email_smtp(recipient_email, subject, html_content, from_email=from_email, attachments=attachments)
        
        # Initialize Resend client
        resend.api_key = api_key
        
        # Send email
        payload = {
            'from': from_email,
            'to': [recipient_email],
            'subject': subject,
            'html': html_content
        }
        prepared_attachments = _prepare_email_attachments(attachments)
        if prepared_attachments:
            payload['attachments'] = [{
                'filename': item['filename'],
                'content': _base64.b64encode(item['data']).decode('utf-8'),
                'type': item['content_type'],
            } for item in prepared_attachments]

        response = resend.Emails.send(payload)
        
        if isinstance(response, dict) and response.get('id'):
            app.logger.info(f'✓ Email sent to {recipient_email} (ID: {response["id"]})')
            return {'success': True, 'message': 'Email sent successfully', 'email_id': response['id']}
        else:
            response_text = str(response)
            app.logger.error(f'✗ Failed to send email to {recipient_email}: {response_text}')
            smtp_result = _send_email_smtp(recipient_email, subject, html_content, from_email=from_email, attachments=attachments)
            if smtp_result.get('success'):
                return smtp_result
            return {'success': False, 'message': response_text, 'email_id': None}
    
    except Exception as e:
        app.logger.error(f'✗ Exception sending email to {recipient_email}: {str(e)}')
        smtp_result = _send_email_smtp(recipient_email, subject, html_content, from_email=from_email, attachments=attachments)
        if smtp_result.get('success'):
            return smtp_result
        return {'success': False, 'message': str(e), 'email_id': None}


def send_email_verification_otp(recipient_email, otp_code, purpose='signup', recipient_name=None):
    purpose_label = 'account creation' if purpose == 'signup' else 'staff account setup'
    expires_minutes = max(1, int(_otp_settings()['ttl_seconds'] // 60))
    html_content = render_template(
        'email/verify_email_otp.html',
        otp_code=otp_code,
        recipient_name=recipient_name,
        purpose_label=purpose_label,
        expires_minutes=expires_minutes,
    )
    return send_email_resend(
        recipient_email=recipient_email,
        subject='Your Email Verification Code - Makokha Medical Centre',
        html_content=html_content,
        from_email=os.getenv('RESEND_FROM_EMAIL') or os.getenv('EMAIL_NOREPLY')
    )


def send_verification_email(user):
    """Send email verification link to user
    
    Args:
        user: User object (must have id, email, first_name)
    
    Returns:
        dict with success status
    """
    try:
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        user.email_verification_token = verification_token
        db.session.commit()
        
        # Create verification link
        verify_url = url_for('verify_email', token=verification_token, _external=True)
        
        # Build email content
        html_content = render_template('email/verify_email.html',
                                      user=user,
                                      verify_url=verify_url)
        
        # Send email
        result = send_email_resend(
            recipient_email=user.email,
            subject='Verify Your Email - Makokha Medical Centre',
            html_content=html_content,
            from_email=_resolve_sender_email(os.getenv('EMAIL_NOREPLY'), os.getenv('RESEND_FROM_EMAIL'))
        )
        
        return result
    
    except Exception as e:
        app.logger.error(f'Error sending verification email to {user.email}: {str(e)}')
        return {'success': False, 'message': str(e), 'email_id': None}


def send_password_reset_email(user, token):
    """Send password reset link to user
    
    Args:
        user: User object
        token: Reset token (generated by itsdangerous serializer)
    
    Returns:
        dict with success status
    """
    try:
        from_email = _resolve_sender_email(os.getenv('EMAIL_NOREPLY'), os.getenv('RESEND_FROM_EMAIL'))
        if not from_email:
            app.logger.error('No valid sender configured for password reset email')
            return {'success': False, 'message': 'Email sender not configured', 'email_id': None}

        # Create reset link
        reset_url = url_for('reset_password', token=token, _external=True)
        
        # Build email content
        html_content = render_template('email/password_reset.html',
                                      user=user,
                                      reset_url=reset_url)
        
        # Send email from noreply address
        result = send_email_resend(
            recipient_email=user.email,
            subject='Reset Your Password - Makokha Medical Centre',
            html_content=html_content,
            from_email=from_email
        )
        
        return result
    
    except Exception as e:
        app.logger.error(f'Error sending password reset email to {user.email}: {str(e)}')
        return {'success': False, 'message': str(e), 'email_id': None}


def send_welcome_email(user):
    """Send welcome email to newly activated user
    
    Args:
        user: User object
    
    Returns:
        dict with success status
    """
    try:
        role = (getattr(user, 'role', None) or '').strip().lower()
        default_from = _resolve_sender_email(os.getenv('RESEND_FROM_EMAIL'), os.getenv('EMAIL_NOREPLY'))
        from_email = default_from
        if role == 'doctor' and os.getenv('EMAIL_DOCTORS'):
            from_email = os.getenv('EMAIL_DOCTORS')
        elif role == 'admin' and os.getenv('EMAIL_ADMIN'):
            from_email = os.getenv('EMAIL_ADMIN')
        from_email = _resolve_sender_email(from_email, default_from)

        role_payload = _RolePayload(_build_role_welcome_payload(user))
        # Build email content
        html_content = render_template('email/welcome.html', user=user, role_payload=role_payload)
        subject = f"Welcome to Makokha Medical Centre - {role_payload.get('headline', 'Account Ready')}"
        
        # Send email
        result = send_email_resend(
            recipient_email=user.email,
            subject=subject,
            html_content=html_content,
            from_email=from_email
        )
        if not result.get('success'):
            app.logger.warning(f'Welcome email send failed for {user.email}: {result.get("message")}')
            if from_email and default_from and from_email != default_from:
                # Retry with designated default sender
                retry = send_email_resend(
                    recipient_email=user.email,
                    subject=subject,
                    html_content=html_content,
                    from_email=default_from
                )
                if retry.get('success'):
                    return retry
                app.logger.warning(f'Welcome email retry failed for {user.email}: {retry.get("message")}')
                return retry
        return result
    
    except Exception as e:
        app.logger.error(f'Error sending welcome email to {user.email}: {str(e)}')
        return {'success': False, 'message': str(e), 'email_id': None}


def send_admin_notification_email(subject, html_content):
    """Send notification email to admin
    
    Args:
        subject: Email subject
        html_content: HTML email content
    
    Returns:
        dict with success status
    """
    try:
        admin_email = os.getenv('EMAIL_ADMIN', 'admin@makokhamedicalcentre.top')
        
        result = send_email_resend(
            recipient_email=admin_email,
            subject=f'[Admin Notification] {subject}',
            html_content=html_content,
            from_email=os.getenv('EMAIL_ADMIN')
        )
        
        return result
    
    except Exception as e:
        app.logger.error(f'Error sending admin notification: {str(e)}')
        return {'success': False, 'message': str(e), 'email_id': None}


def _format_datetime_display(value):
    if not value:
        return 'TBD'
    try:
        normalized = value
        if getattr(normalized, 'tzinfo', None) is not None:
            normalized = normalized.astimezone(EAT_TZ).replace(tzinfo=None)
        return normalized.strftime('%a, %b %d, %Y at %I:%M %p')
    except Exception:
        return str(value)


def _appointment_email_marker(appointment_id, email_key):
    return f'appointment:{appointment_id}:email:{email_key}'


def _appointment_email_already_sent(appointment_id, email_key):
    marker = _appointment_email_marker(appointment_id, email_key)
    try:
        return db.session.query(AuditLog.id).filter(
            AuditLog.action == 'appointment_email_dispatch',
            AuditLog.description == marker
        ).first() is not None
    except Exception:
        return False


def _appointment_email_actor_user_id(appointment):
    try:
        patient_user_id = getattr(getattr(appointment, 'patient', None), 'user_id', None)
        if patient_user_id:
            return patient_user_id
    except Exception:
        pass
    try:
        doctor_user_id = getattr(getattr(appointment, 'doctor', None), 'user_id', None)
        if doctor_user_id:
            return doctor_user_id
    except Exception:
        pass
    try:
        if current_user and getattr(current_user, 'is_authenticated', False):
            return current_user.id
    except Exception:
        pass
    fallback_user = User.query.order_by(User.id.asc()).first()
    return getattr(fallback_user, 'id', None)


def _mark_appointment_email_sent(appointment, email_key):
    marker = _appointment_email_marker(appointment.id, email_key)
    try:
        if _appointment_email_already_sent(appointment.id, email_key):
            return True
        actor_user_id = _appointment_email_actor_user_id(appointment)
        if not actor_user_id:
            return False
        db.session.add(AuditLog(
            user_id=actor_user_id,
            action='appointment_email_dispatch',
            description=marker,
            ip_address=request.remote_addr if request else None
        ))
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _appointment_context(appointment):
    patient = getattr(appointment, 'patient', None)
    doctor = getattr(appointment, 'doctor', None)
    patient_user = getattr(patient, 'user', None)
    doctor_user = getattr(doctor, 'user', None)
    patient_name = safe_display_name(patient_user) if patient_user else 'Patient'
    doctor_name = safe_display_name(doctor_user) if doctor_user else 'Doctor'
    return patient_user, doctor_user, patient_name, doctor_name


def _build_appointment_invoice_attachment(appointment, payment=None, suffix='invoice'):
    amount = None
    currency = 'KES'
    payment_reference = None
    if payment is not None:
        amount = getattr(payment, 'amount', None)
        currency = getattr(payment, 'currency', None) or 'KES'
        payment_reference = getattr(payment, 'provider_reference', None)
    if amount is None:
        amount = getattr(appointment, 'payment_amount', None)
    if amount is None:
        try:
            amount = getattr(getattr(appointment, 'doctor', None), 'consultation_fee', None)
        except Exception:
            amount = None
    if amount is None:
        amount = 0.0

    patient_user, _, patient_name, doctor_name = _appointment_context(appointment)
    patient_email = getattr(patient_user, 'email', None) or 'N/A'
    appointment_time = _format_datetime_display(getattr(appointment, 'appointment_date', None))

    filename = f'appointment_{appointment.id}_{suffix}.pdf'
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        y = 760
        line_height = 20

        pdf.setFont('Helvetica-Bold', 16)
        pdf.drawString(72, y, 'Makokha Medical Centre - Payment Invoice')
        y -= 35

        pdf.setFont('Helvetica', 11)
        rows = [
            f'Invoice Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            f'Appointment ID: #{appointment.id}',
            f'Patient: {patient_name}',
            f'Patient Email: {patient_email}',
            f'Doctor: {doctor_name}',
            f'Appointment Time: {appointment_time}',
            f'Consultation Type: {(getattr(appointment, "consultation_type", None) or "N/A").title()}',
            f'Amount Paid: {currency} {float(amount):,.2f}',
            f'Payment Method: {getattr(appointment, "payment_method", None) or "Online"}',
            f'Payment Reference: {payment_reference or "N/A"}',
        ]

        for row in rows:
            pdf.drawString(72, y, row)
            y -= line_height

        pdf.showPage()
        pdf.save()
        buffer.seek(0)
        return {
            'filename': filename,
            'content_type': 'application/pdf',
            'data': buffer.read()
        }
    except Exception:
        fallback = (
            f'Makokha Medical Centre - Invoice\n'
            f'Appointment ID: {appointment.id}\n'
            f'Patient: {patient_name}\n'
            f'Doctor: {doctor_name}\n'
            f'Appointment Time: {appointment_time}\n'
            f'Amount Paid: {currency} {float(amount):,.2f}\n'
            f'Payment Reference: {payment_reference or "N/A"}\n'
        )
        return {
            'filename': f'appointment_{appointment.id}_{suffix}.txt',
            'content_type': 'text/plain',
            'data': fallback.encode('utf-8')
        }


def _send_patient_appointment_email(appointment, email_key, subject, template_name, template_context=None, attachments=None, dedupe=True):
    if not appointment:
        return {'success': False, 'message': 'appointment_missing'}
    if dedupe and _appointment_email_already_sent(appointment.id, email_key):
        return {'success': True, 'skipped': True, 'message': 'already_sent'}

    patient_user, doctor_user, patient_name, doctor_name = _appointment_context(appointment)
    recipient_email = getattr(patient_user, 'email', None)
    if not _is_valid_email_address(recipient_email):
        return {'success': False, 'message': 'invalid_patient_email'}

    context = {
        'appointment': appointment,
        'patient_user': patient_user,
        'doctor_user': doctor_user,
        'patient_name': patient_name,
        'doctor_name': doctor_name,
        'appointment_time': _format_datetime_display(getattr(appointment, 'appointment_date', None)),
        'login_url': url_for('login', _external=True),
        'payment_url': url_for('payment_by_appointment', appointment_id=appointment.id, _external=True),
    }
    if template_context:
        context.update(template_context)

    html_content = render_template(template_name, **context)
    result = send_email_resend(
        recipient_email=recipient_email,
        subject=subject,
        html_content=html_content,
        from_email=_resolve_sender_email(os.getenv('EMAIL_NOREPLY'), os.getenv('RESEND_FROM_EMAIL')),
        attachments=attachments,
    )
    if result.get('success'):
        _mark_appointment_email_sent(appointment, email_key)
    return result


def _send_booking_workflow_email(appointment, payment=None):
    if not appointment:
        return {'success': False, 'message': 'appointment_missing'}

    payment_status = (getattr(payment, 'status', None) or getattr(appointment, 'payment_status', None) or '').strip().lower()
    amount = getattr(payment, 'amount', None)
    if amount is None:
        amount = getattr(appointment, 'payment_amount', None)
    if amount is None:
        amount = getattr(getattr(appointment, 'doctor', None), 'consultation_fee', None)

    if payment_status == 'paid':
        invoice = _build_appointment_invoice_attachment(appointment, payment=payment, suffix='booking_paid_invoice')
        return _send_patient_appointment_email(
            appointment=appointment,
            email_key='booking_paid',
            subject='Appointment booked and payment confirmed',
            template_name='email/appointment_booking.html',
            template_context={
                'payment_status': 'paid',
                'amount': amount,
                'currency': getattr(payment, 'currency', None) or 'KES',
            },
            attachments=[invoice],
        )

    return _send_patient_appointment_email(
        appointment=appointment,
        email_key='booking_unpaid',
        subject='Appointment booked - payment pending',
        template_name='email/appointment_booking.html',
        template_context={
            'payment_status': 'unpaid',
            'amount': amount,
            'currency': getattr(payment, 'currency', None) or 'KES',
        },
    )


def _send_later_payment_email(appointment, payment=None):
    if not appointment:
        return {'success': False, 'message': 'appointment_missing'}
    invoice = _build_appointment_invoice_attachment(appointment, payment=payment, suffix='payment_invoice')
    amount = getattr(payment, 'amount', None)
    if amount is None:
        amount = getattr(appointment, 'payment_amount', None)
    return _send_patient_appointment_email(
        appointment=appointment,
        email_key='payment_received',
        subject='Payment received - thank you',
        template_name='email/appointment_payment_received.html',
        template_context={
            'amount': amount,
            'currency': getattr(payment, 'currency', None) or 'KES',
            'provider_reference': getattr(payment, 'provider_reference', None) if payment else None,
        },
        attachments=[invoice],
    )


def _send_day_of_appointment_reminder(appointment):
    if not appointment:
        return {'success': False, 'message': 'appointment_missing'}
    reminder_key = f"day_reminder_{getattr(appointment, 'appointment_date', now_eat()).date().isoformat()}"
    result = _send_patient_appointment_email(
        appointment=appointment,
        email_key=reminder_key,
        subject='Appointment reminder - today',
        template_name='email/appointment_day_reminder.html',
        template_context={
            'consultation_type': (getattr(appointment, 'consultation_type', None) or 'consultation').title(),
        },
    )
    if result.get('success'):
        try:
            appointment.reminder_sent_at = now_eat()
            db.session.add(appointment)
            db.session.commit()
        except Exception:
            db.session.rollback()
    return result


def _send_appointment_outcome_email(appointment, outcome=None):
    if not appointment:
        return {'success': False, 'message': 'appointment_missing'}

    resolved_outcome = (outcome or getattr(appointment, 'status', None) or '').strip().lower()
    if resolved_outcome == 'missed' or (
        not resolved_outcome and (getattr(appointment, 'call_status', None) or '').strip().lower() == 'missed'
    ):
        resolved_outcome = 'missed'

    if resolved_outcome == 'completed':
        testimonial = Testimonial.query.filter_by(appointment_id=appointment.id).first()
        reviewed = testimonial is not None
        return _send_patient_appointment_email(
            appointment=appointment,
            email_key='outcome_completed_reviewed' if reviewed else 'outcome_completed_review_pending',
            subject='Consultation completed - thank you' if reviewed else 'Consultation completed - share your feedback',
            template_name='email/appointment_outcome.html',
            template_context={
                'outcome': 'completed',
                'reviewed': reviewed,
                'review_prompt': not reviewed,
            },
        )

    if resolved_outcome not in ('incomplete', 'missed', 'cancelled', 'rescheduled'):
        return {'success': False, 'message': f'unsupported_outcome:{resolved_outcome}'}

    return _send_patient_appointment_email(
        appointment=appointment,
        email_key=f'outcome_{resolved_outcome}',
        subject=f'Appointment update - {resolved_outcome.title()}',
        template_name='email/appointment_outcome.html',
        template_context={
            'outcome': resolved_outcome,
            'reviewed': False,
            'review_prompt': False,
        },
    )


def dispatch_day_of_appointment_reminders(target_date=None, dry_run=False):
    now = now_eat()
    if target_date:
        start_dt = datetime(target_date.year, target_date.month, target_date.day, 0, 0, 0, tzinfo=EAT_TZ)
        end_dt = datetime(target_date.year, target_date.month, target_date.day, 23, 59, 59, 999999, tzinfo=EAT_TZ)
    else:
        start_dt = now
        end_dt = now + timedelta(hours=24)

    candidates = Appointment.query.filter(
        Appointment.appointment_date >= start_dt,
        Appointment.appointment_date <= end_dt,
        Appointment.status.in_(['pending', 'confirmed', 'rescheduled'])
    ).all()

    stats = {
        'window_start': start_dt.isoformat(),
        'window_end': end_dt.isoformat(),
        'target_date': target_date.isoformat() if target_date else None,
        'dry_run': bool(dry_run),
        'candidates': len(candidates),
        'already_sent': 0,
        'sent': 0,
        'failed': 0,
    }

    for appointment in candidates:
        try:
            if appointment.reminder_sent_at and appointment.appointment_date and appointment.reminder_sent_at.date() == appointment.appointment_date.date():
                stats['already_sent'] += 1
                continue
            if dry_run:
                continue
            result = _send_day_of_appointment_reminder(appointment)
            if result.get('success'):
                stats['sent'] += 1
            else:
                stats['failed'] += 1
        except Exception:
            stats['failed'] += 1
            continue

    return stats


def dispatch_appointment_outcome_emails():
    now = now_eat()
    candidates = Appointment.query.filter(
        Appointment.appointment_date <= now + timedelta(hours=1)
    ).all()

    for appointment in candidates:
        try:
            status = (appointment.status or '').strip().lower()
            call_status = (appointment.call_status or '').strip().lower()
            outcome = None
            if status in ('completed', 'incomplete', 'cancelled', 'rescheduled'):
                outcome = status
            elif call_status == 'missed':
                outcome = 'missed'
            if outcome:
                _send_appointment_outcome_email(appointment, outcome=outcome)
        except Exception:
            continue


@app.route('/api/email-otp/request', methods=['POST'])
def request_email_otp():
    try:
        data = request.get_json(silent=True) or request.form or {}
        email = _normalize_email_address(data.get('email'))
        purpose = (data.get('purpose') or 'signup').strip().lower()
        if purpose not in ('signup', 'admin_create_user', 'admin_update_user_email', 'login_verify_email'):
            return jsonify({'success': False, 'error': 'invalid_purpose'}), 400

        if purpose in ('admin_create_user', 'admin_update_user_email') and not current_user_has_role('admin'):
            return jsonify({'success': False, 'error': 'access_denied'}), 403

        target_user_id = None
        if purpose == 'admin_update_user_email':
            try:
                target_user_id = int(data.get('user_id') or 0)
            except Exception:
                target_user_id = 0
            if not target_user_id:
                return jsonify({'success': False, 'error': 'missing_user_id'}), 400

        if purpose == 'login_verify_email':
            pending_user_id = session.get('pending_email_verify_user_id')
            if not pending_user_id:
                return jsonify({'success': False, 'error': 'verification_session_missing'}), 403
            pending_user = db.session.get(User, int(pending_user_id))
            if not pending_user:
                session.pop('pending_email_verify_user_id', None)
                session.pop('pending_email_verify_remember', None)
                session.pop('pending_email_verify_next', None)
                return jsonify({'success': False, 'error': 'verification_user_missing'}), 404
            if _normalize_email_address(getattr(pending_user, 'email', '')) != email:
                return jsonify({'success': False, 'error': 'email_mismatch'}), 400
            if bool(getattr(pending_user, 'email_verified', False)):
                return jsonify({'success': False, 'error': 'already_verified'}), 400

        if not _is_valid_email_address(email):
            return jsonify({'success': False, 'error': 'invalid_email'}), 400

        existing_user = User.query.filter_by(email_hash=_hash_value(email)).first()
        if existing_user and purpose in ('signup', 'admin_create_user'):
            return jsonify({'success': False, 'error': 'email_already_registered'}), 400
        if existing_user and purpose == 'admin_update_user_email' and int(existing_user.id) != int(target_user_id or 0):
            return jsonify({'success': False, 'error': 'email_already_registered'}), 400

        settings = _otp_settings()
        now = _otp_now()
        challenge = _find_active_otp_challenge(email, purpose)

        if challenge and challenge.resend_allowed_at and now < _otp_normalize(challenge.resend_allowed_at):
            wait_seconds = int((_otp_normalize(challenge.resend_allowed_at) - now).total_seconds())
            return jsonify({'success': False, 'error': 'resend_cooldown', 'retry_after_seconds': max(1, wait_seconds)}), 429

        otp_code = _generate_numeric_otp()
        recipient_name = data.get('name') or None
        send_result = send_email_verification_otp(email, otp_code, purpose=purpose, recipient_name=recipient_name)
        if not send_result.get('success'):
            return jsonify({'success': False, 'error': 'send_failed', 'message': send_result.get('message')}), 502

        if not challenge:
            challenge = EmailOTPChallenge(
                email_hash=_hash_value(email),
                purpose=purpose,
                otp_hash=_otp_hash(email, otp_code),
                expires_at=now + timedelta(seconds=settings['ttl_seconds']),
                resend_allowed_at=now + timedelta(seconds=settings['resend_seconds']),
                attempts=0,
                max_attempts=settings['max_attempts'],
                verified=False,
                consumed=False,
                created_by_user_id=getattr(current_user, 'id', None) if getattr(current_user, 'is_authenticated', False) else None,
                created_at=now,
            )
            db.session.add(challenge)
        else:
            challenge.otp_hash = _otp_hash(email, otp_code)
            challenge.expires_at = now + timedelta(seconds=settings['ttl_seconds'])
            challenge.resend_allowed_at = now + timedelta(seconds=settings['resend_seconds'])
            challenge.attempts = 0
            challenge.max_attempts = settings['max_attempts']
            challenge.verified = False
            challenge.verified_at = None
            challenge.consumed = False

        db.session.commit()
        return jsonify({
            'success': True,
            'challenge_id': challenge.id,
            'expires_in_seconds': settings['ttl_seconds'],
            'resend_after_seconds': settings['resend_seconds']
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Email OTP request failed: {str(e)}')
        return jsonify({'success': False, 'error': 'otp_request_failed'}), 500


@app.route('/api/email-otp/verify', methods=['POST'])
def verify_email_otp():
    try:
        data = request.get_json(silent=True) or request.form or {}
        email = _normalize_email_address(data.get('email'))
        purpose = (data.get('purpose') or 'signup').strip().lower()
        otp_code = (data.get('otp_code') or '').strip()
        challenge_id = data.get('challenge_id')

        if purpose not in ('signup', 'admin_create_user', 'admin_update_user_email', 'login_verify_email'):
            return jsonify({'success': False, 'error': 'invalid_purpose'}), 400
        if purpose in ('admin_create_user', 'admin_update_user_email') and not current_user_has_role('admin'):
            return jsonify({'success': False, 'error': 'access_denied'}), 403
        pending_user = None
        if purpose == 'login_verify_email':
            pending_user_id = session.get('pending_email_verify_user_id')
            if not pending_user_id:
                return jsonify({'success': False, 'error': 'verification_session_missing'}), 403
            pending_user = db.session.get(User, int(pending_user_id))
            if not pending_user:
                session.pop('pending_email_verify_user_id', None)
                session.pop('pending_email_verify_remember', None)
                session.pop('pending_email_verify_next', None)
                return jsonify({'success': False, 'error': 'verification_user_missing'}), 404
            if _normalize_email_address(getattr(pending_user, 'email', '')) != email:
                return jsonify({'success': False, 'error': 'email_mismatch'}), 400
        if not _is_valid_email_address(email):
            return jsonify({'success': False, 'error': 'invalid_email'}), 400
        if not (otp_code.isdigit() and len(otp_code) >= 4):
            return jsonify({'success': False, 'error': 'invalid_code'}), 400

        challenge = None
        if challenge_id:
            challenge = db.session.get(EmailOTPChallenge, int(challenge_id))
        if not challenge:
            challenge = _find_active_otp_challenge(email, purpose)
        if not challenge:
            return jsonify({'success': False, 'error': 'challenge_not_found'}), 404
        if challenge.email_hash != _hash_value(email) or challenge.purpose != purpose:
            return jsonify({'success': False, 'error': 'challenge_mismatch'}), 400
        if challenge.consumed:
            return jsonify({'success': False, 'error': 'challenge_already_used'}), 400
        if _otp_normalize(challenge.expires_at) <= _otp_now():
            return jsonify({'success': False, 'error': 'code_expired'}), 400
        if challenge.attempts >= challenge.max_attempts:
            return jsonify({'success': False, 'error': 'too_many_attempts'}), 429

        submitted_hash = _otp_hash(email, otp_code)
        if not hmac.compare_digest(challenge.otp_hash, submitted_hash):
            challenge.attempts = int(challenge.attempts or 0) + 1
            db.session.add(challenge)
            db.session.commit()
            return jsonify({'success': False, 'error': 'invalid_code', 'attempts_remaining': max(0, challenge.max_attempts - challenge.attempts)}), 400

        challenge.verified = True
        challenge.verified_at = _otp_now()
        db.session.add(challenge)

        if purpose == 'login_verify_email' and pending_user:
            challenge.consumed = True
            pending_user.email_verified = True
            db.session.add(pending_user)

        db.session.commit()

        if purpose == 'login_verify_email' and pending_user:
            remember = bool(session.get('pending_email_verify_remember'))
            next_page = session.get('pending_email_verify_next')
            login_user(pending_user, remember=remember)
            session.pop('pending_email_verify_user_id', None)
            session.pop('pending_email_verify_remember', None)
            session.pop('pending_email_verify_next', None)
            redirect_url = next_page if next_page else url_for('index')
            return jsonify({'success': True, 'challenge_id': challenge.id, 'verified': True, 'login_verified': True, 'redirect_url': redirect_url})

        return jsonify({'success': True, 'challenge_id': challenge.id, 'verified': True})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Email OTP verify failed: {str(e)}')
        return jsonify({'success': False, 'error': 'otp_verify_failed'}), 500


def _consume_verified_otp_challenge(email, purpose, challenge_id, require_admin=False):
    try:
        if require_admin and not current_user_has_role('admin'):
            return None, 'access_denied'
        if not challenge_id:
            return None, 'missing_otp_challenge'
        challenge = db.session.get(EmailOTPChallenge, int(challenge_id))
        if not challenge:
            return None, 'otp_challenge_not_found'
        if challenge.email_hash != _hash_value(_normalize_email_address(email)) or challenge.purpose != purpose:
            return None, 'otp_challenge_mismatch'
        if challenge.consumed:
            return None, 'otp_challenge_consumed'
        if _otp_normalize(challenge.expires_at) <= _otp_now():
            return None, 'otp_challenge_expired'
        if not challenge.verified:
            return None, 'email_not_verified_by_otp'
        challenge.consumed = True
        db.session.add(challenge)
        return challenge, None
    except Exception:
        return None, 'otp_challenge_invalid'


def configure_app():
    """Configure Flask application with environment variables"""
    app.config.from_object(Config)

    def _normalize_database_url(raw_url):
        if not raw_url:
            return None
        normalized = str(raw_url).strip()
        if not normalized:
            return None
        if normalized.startswith('postgres://'):
            normalized = 'postgresql://' + normalized[len('postgres://'):]
        if normalized.startswith('postgresql://'):
            parsed_url = urllib.parse.urlparse(normalized)
            decoded_path = urllib.parse.unquote(parsed_url.path)
            normalized = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                decoded_path,
                parsed_url.params,
                parsed_url.query,
                parsed_url.fragment
            ))
        return normalized

    def _database_identity(uri):
        uri_value = (uri or '').strip()
        if not uri_value:
            return {'scheme': 'unknown', 'host': 'unknown', 'database': 'unknown', 'fingerprint': 'unknown'}
        try:
            if uri_value.startswith('sqlite:'):
                parsed_sqlite = urllib.parse.urlparse(uri_value)
                db_path = parsed_sqlite.path or ''
                db_name = os.path.basename(db_path) if db_path else ':memory:'
                return {
                    'scheme': 'sqlite',
                    'host': 'local',
                    'database': db_name,
                    'fingerprint': f'sqlite|{db_name}'
                }

            parsed = urllib.parse.urlparse(uri_value)
            db_name = (parsed.path or '/').lstrip('/') or 'unknown'
            host = parsed.hostname or 'unknown'
            scheme = parsed.scheme or 'unknown'
            return {
                'scheme': scheme,
                'host': host,
                'database': db_name,
                'fingerprint': f'{scheme}|{host}|{db_name}'
            }
        except Exception:
            return {'scheme': 'unknown', 'host': 'unknown', 'database': 'unknown', 'fingerprint': 'unknown'}

    def _enforce_database_guard(identity):
        expected_fingerprint = (os.getenv('EXPECTED_DATABASE_FINGERPRINT') or '').strip()
        if expected_fingerprint and identity.get('fingerprint') != expected_fingerprint:
            raise RuntimeError(
                f"Database fingerprint mismatch. expected='{expected_fingerprint}' actual='{identity.get('fingerprint')}'. "
                "Refusing startup to avoid writing to an unintended database."
            )

        required_in_production = os.getenv('REQUIRE_DATABASE_URL_IN_PRODUCTION', '1').strip().lower() in ('1', 'true', 'yes', 'on')
        is_production_env = (os.getenv('ENVIRONMENT', '') or '').strip().lower() == 'production'
        if required_in_production and is_production_env and not os.getenv('DATABASE_URL'):
            raise RuntimeError('DATABASE_URL is required in production but is not set.')

    # Security
    app.config['ASYNC_MODE'] = detected_async
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production-12345')
    app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_UPLOAD_SIZE', 5 * 1024 * 1024))
    
    # Database configuration with deterministic source selection and normalization
    database_url = _normalize_database_url(
        os.getenv('DATABASE_URL')
        or app.config.get('SQLALCHEMY_DATABASE_URI')
        or getattr(Config, 'SQLALCHEMY_DATABASE_URI', None)
    )
    if not database_url:
        # Safe local-dev fallback. In production this is blocked by REQUIRE_DATABASE_URL_IN_PRODUCTION.
        fallback_sqlite_path = os.path.join(app.root_path, 'instance', 'telemed.db').replace('\\', '/')
        database_url = f'sqlite:///{fallback_sqlite_path}'
        app.logger.warning('DATABASE_URL not set; using local fallback database at %s', fallback_sqlite_path)

    db_identity = _database_identity(database_url)
    _enforce_database_guard(db_identity)
    app.logger.info(
        'Database target resolved: scheme=%s host=%s database=%s',
        db_identity.get('scheme'),
        db_identity.get('host'),
        db_identity.get('database')
    )

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 10,  # Reduced for better compatibility
        'max_overflow': 20,
        'poolclass': QueuePool,  # Use the imported class, not a string
        'echo': False
    }
    
    # Email configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
    
    # OAuth configuration
    app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
    app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')
    app.config['FACEBOOK_OAUTH_CLIENT_ID'] = os.getenv('FACEBOOK_OAUTH_CLIENT_ID')
    app.config['FACEBOOK_OAUTH_CLIENT_SECRET'] = os.getenv('FACEBOOK_OAUTH_CLIENT_SECRET')
    
    # File uploads
    app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
    app.config['ENCRYPTION_KEY'] = os.getenv('ENCRYPTION_KEY', 'dev-encryption-key-32-chars-long!123456')
    
    # Payment providers
    app.config['STRIPE_SECRET_KEY'] = os.getenv('STRIPE_SECRET_KEY')
    app.config['STRIPE_WEBHOOK_SECRET'] = os.getenv('STRIPE_WEBHOOK_SECRET')

    # Payment webhook and idempotency settings
    # PAYMENT_PROVIDER_SECRETS should be a JSON object string, e.g. {"mpesa":"secret","stripe":"whsec_xxx"}
    try:
        _pp = os.getenv('PAYMENT_PROVIDER_SECRETS')
        app.config['PAYMENT_PROVIDER_SECRETS'] = json.loads(_pp) if _pp else {}
    except Exception:
        app.config['PAYMENT_PROVIDER_SECRETS'] = {}
    # WEBHOOK_IP_ALLOWLIST should be comma-separated CIDRs e.g. "3.18.12.63/32, 3.130.192.231/32"
    _ip_allow = os.getenv('WEBHOOK_IP_ALLOWLIST')
    app.config['WEBHOOK_IP_ALLOWLIST'] = [p.strip() for p in _ip_allow.split(',')] if _ip_allow else []
    try:
        app.config['IDEMPOTENCY_TTL_DAYS'] = int(os.getenv('IDEMPOTENCY_TTL_DAYS', '7'))
    except Exception:
        app.config['IDEMPOTENCY_TTL_DAYS'] = 7
    
    # Logging
    app.config['LOG_LEVEL'] = os.getenv('LOG_LEVEL', 'INFO')

    # Session / cookie security defaults
    # Use secure cookies only in production (allow local dev over HTTP otherwise)
    is_production = os.getenv('ENVIRONMENT', '').lower() == 'production'
    app.config.setdefault('SESSION_COOKIE_SECURE', is_production)
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
    app.config.setdefault('REMEMBER_COOKIE_SECURE', is_production)
    app.config.setdefault('REMEMBER_COOKIE_HTTPONLY', True)
    app.config.setdefault('PREFERRED_URL_SCHEME', 'https')

    # ICE / TURN configuration with rotation support
    # Supports: XIRSYS (primary), static env TURN_URLS, Google STUN (fallback)
    ice_servers = []
    
    # Try XIRSYS first (recommended for production)
    xirsys_servers = get_xirsys_turn_servers()
    if xirsys_servers:
        ice_servers.extend(xirsys_servers)
        print(f"✓ Loaded {len(xirsys_servers)} XIRSYS TURN servers")
    
    # Fallback to static TURN configuration from env
    turn_urls = [u.strip() for u in (os.getenv('TURN_URLS') or os.getenv('TURN_URL','')).split(',') if u.strip()]
    turn_user = os.getenv('TURN_USER')
    turn_pass = os.getenv('TURN_PASS')
    
    if turn_urls and turn_urls != ['']:
        for url in turn_urls:
            entry = { 'urls': url }
            if turn_user and turn_pass:
                entry['username'] = turn_user
                entry['credential'] = turn_pass
            ice_servers.append(entry)
        print(f"✓ Loaded {len(turn_urls)} static TURN servers from env")
    
    # Always include Google STUN as last resort fallback
    ice_servers.append({ 'urls': 'stun:stun.l.google.com:19302' })
    ice_servers.append({ 'urls': 'stun:stun1.l.google.com:19302' })

    app.config['ICE_SERVERS'] = ice_servers
    app.config['ICE_CRED_ROTATE_SECONDS'] = int(os.getenv('ICE_CRED_ROTATE_SECONDS', '3600'))

configure_app()

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def handle_unauthorized():
    """Return JSON 401 for API/AJAX requests instead of redirecting to login."""
    if (
        request.path.startswith('/api/')
        or request.path.startswith('/admin/api/')
        or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or request.accept_mimetypes.best == 'application/json'
    ):
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    return redirect(url_for('login', next=request.url))

oauth = OAuth(app)


# Security headers to harden responses
@app.after_request
def set_security_headers(response):
    try:
        # Prevent clickjacking
        response.headers.setdefault('X-Frame-Options', 'DENY')
        # Prevent MIME type sniffing
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        # Basic Referrer policy
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        # HSTS - enforce HTTPS for 1 week (adjust in production)
        response.headers.setdefault('Strict-Transport-Security', 'max-age=604800; includeSubDomains')

        env_policy = os.getenv('PERMISSIONS_POLICY')
        if env_policy:
            response.headers.setdefault('Permissions-Policy', env_policy)
        else:
            try:
                # Allow camera/microphone on call/communication pages (same-origin only)
                path = request.path or ''
                allow_camera_mic = False
                # Paths that typically need media access. Use substring checks so
                # routes like '/patient/communication' are covered.
                if ('communication' in path) or path.startswith('/video') or '/call' in path or 'consultation-room' in path:
                    allow_camera_mic = True
                if allow_camera_mic:
                    # Allow camera, microphone and geolocation for call/communication pages (same-origin)
                    response.headers.setdefault('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(self)')
                else:
                    # Deny by default
                    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            except Exception:
                # On any error, be conservative and deny media access
                response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    except Exception:
        pass
    return response


@app.before_request
def capture_patient_location_before_request():
    _capture_patient_location_from_request()

# ============================================
# DATABASE INITIALIZATION
# ============================================
def create_default_users():
    """Create default admin account from environment variables if it doesn't exist."""
    with app.app_context():
        admin_username = (os.getenv('ADMIN_USERNAME') or '').strip()
        admin_email = (os.getenv('ADMIN_EMAIL') or '').strip()
        admin_password = os.getenv('ADMIN_PASSWORD') or ''
        admin_first_name = (os.getenv('ADMIN_FIRST_NAME') or 'System').strip()
        admin_last_name = (os.getenv('ADMIN_LAST_NAME') or 'Administrator').strip()
        admin_phone = (os.getenv('ADMIN_PHONE') or '').strip()
        admin_timezone = (os.getenv('ADMIN_TIMEZONE') or 'Africa/Nairobi').strip()

        if not admin_username or not admin_email or not admin_password:
            print('⚠ Admin bootstrap skipped: set ADMIN_USERNAME, ADMIN_EMAIL, and ADMIN_PASSWORD to auto-create admin user.')
            return

        admin = User.query.filter_by(username=admin_username).first()
        if not admin:
            admin_user = User(
                username=admin_username,
                email=admin_email,
                role='admin',
                is_active=True
            )
            admin_user.set_password(admin_password)
            admin_user.first_name = admin_first_name
            admin_user.last_name = admin_last_name
            admin_user.phone = admin_phone or None
            admin_user.last_known_timezone = admin_timezone
            db.session.add(admin_user)
            print("✓ Default admin account created")
        else:
            admin_updated = False
            if not getattr(admin, 'email', None):
                admin.email = admin_email
                admin_updated = True
            if not getattr(admin, 'first_name', None):
                admin.first_name = admin_first_name
                admin_updated = True
            if not getattr(admin, 'last_name', None):
                admin.last_name = admin_last_name
                admin_updated = True
            if not getattr(admin, 'phone', None) and admin_phone:
                admin.phone = admin_phone
                admin_updated = True
            if not getattr(admin, 'last_known_timezone', None):
                admin.last_known_timezone = admin_timezone
                admin_updated = True
            if admin_updated:
                db.session.add(admin)
            print("✓ Default admin already exists")
        
        try:
            db.session.commit()
            print("✓ Default admin setup completed")
        except Exception as e:
            db.session.rollback()
            print(f"✗ Error creating default admin: {e}")

def initialize_database():
    """Initialize database tables and create default users"""
    with app.app_context():
        try:
            # Create all tables if they don't exist
            db.create_all()
            print("✓ Database tables verified/created")

            existing_user_count = 0
            try:
                existing_user_count = User.query.count()
                print(f"ℹ Startup user count before admin bootstrap: {existing_user_count}")
                if existing_user_count == 0:
                    print("⚠ Database appears empty at startup. Verify DATABASE_URL points to your persistent production database.")
            except Exception as count_error:
                print(f"✗ Unable to count users during startup: {count_error}")

            # Ensure notifications table has expected columns (hotfix for missing migrations)
            try:
                insp = inspect(db.engine)
                if 'notifications' in insp.get_table_names():
                    cols = [c['name'] for c in insp.get_columns('notifications')]
                    if 'call_status' not in cols:
                        try:
                            with db.engine.begin() as conn:
                                conn.execute(text("ALTER TABLE notifications ADD COLUMN call_status VARCHAR(50)"))
                            print('✓ Added missing column notifications.call_status')
                        except Exception as e:
                            print('✗ Failed to add notifications.call_status:', e)
            except Exception as e:
                print('✗ Failed to inspect notifications table:', e)

            # Ensure users table has required columns (hotfix for missing migrations)
            try:
                if 'users' in insp.get_table_names():
                    user_cols = [c['name'] for c in insp.get_columns('users')]
                    needed = {
                        'email_verified': 'BOOLEAN DEFAULT FALSE',
                        'email_verification_token': 'VARCHAR(255)',
                        'password_reset_token': 'VARCHAR(255)',
                        'password_reset_token_expires': 'TIMESTAMP',
                        'allow_user_creation': 'BOOLEAN DEFAULT FALSE',
                        'show_availability': 'BOOLEAN DEFAULT TRUE',
                        'share_data': 'BOOLEAN DEFAULT FALSE',
                        'call_permissions_granted': 'BOOLEAN DEFAULT FALSE',
                        'call_permissions_granted_at': 'TIMESTAMP',
                        'last_known_lat': 'DOUBLE PRECISION',
                        'last_known_lng': 'DOUBLE PRECISION',
                        'last_known_timezone': 'VARCHAR(64)',
                        'account_role': 'VARCHAR(20)',
                        'staff_group': 'VARCHAR(40)',
                        'practitioner_type': 'VARCHAR(60)',
                        'professional_title': 'VARCHAR(80)',
                        'department': 'VARCHAR(100)',
                        'job_category': 'VARCHAR(100)',
                        'bank_account': 'VARCHAR(120)',
                        'bank_name': 'VARCHAR(120)',
                        'bank_account_type': 'VARCHAR(60)',
                        'preferred_payment_method': 'VARCHAR(60)',
                        'public_profile_visible': 'BOOLEAN DEFAULT FALSE',
                        'public_show_consultation_fee': 'BOOLEAN DEFAULT FALSE'
                    }
                    for col, coltype in needed.items():
                        if col not in user_cols:
                            try:
                                with db.engine.begin() as conn:
                                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {coltype}"))
                                print(f'✓ Added missing column users.{col}')
                            except Exception as e:
                                print(f'✗ Failed to add users.{col}:', e)

                    try:
                        with db.engine.begin() as conn:
                            conn.execute(text("""
                                UPDATE users
                                SET account_role = 'patient',
                                    staff_group = NULL,
                                    practitioner_type = NULL
                                WHERE role = 'patient' AND (account_role IS NULL OR account_role = '')
                            """))
                            conn.execute(text("""
                                UPDATE users
                                SET account_role = 'staff',
                                    staff_group = COALESCE(staff_group, 'practitioner'),
                                    practitioner_type = COALESCE(practitioner_type, 'general_practitioner')
                                WHERE role = 'doctor' AND (account_role IS NULL OR account_role = '')
                            """))
                            conn.execute(text("""
                                UPDATE users
                                SET account_role = 'admin',
                                    staff_group = COALESCE(staff_group, 'administration'),
                                    practitioner_type = NULL
                                WHERE role = 'admin' AND (account_role IS NULL OR account_role = '')
                            """))
                        print('✓ Backfilled users account classification defaults')
                    except Exception as e:
                        print('✗ Failed to backfill users account classification:', e)
            except Exception as e:
                print('✗ Failed to inspect users table:', e)

            # Ensure doctors table has practitioner profile columns (hotfix for missing migrations)
            try:
                if 'doctors' in insp.get_table_names():
                    doctor_cols = [c['name'] for c in insp.get_columns('doctors')]
                    doctor_needed = {
                        'license_regulatory_body': 'VARCHAR(120)',
                        'license_issue_date': 'DATE',
                        'license_expiry_date': 'DATE',
                        'license_renewal_status': 'VARCHAR(60)',
                        'awards_merits': 'TEXT'
                    }
                    for col, coltype in doctor_needed.items():
                        if col not in doctor_cols:
                            try:
                                with db.engine.begin() as conn:
                                    conn.execute(text(f"ALTER TABLE doctors ADD COLUMN {col} {coltype}"))
                                print(f'✓ Added missing column doctors.{col}')
                            except Exception as e:
                                print(f'✗ Failed to add doctors.{col}:', e)
            except Exception as e:
                print('✗ Failed to inspect doctors table:', e)

            # Ensure testimonials table exists (hotfix for missing migrations)
            try:
                if 'testimonials' not in insp.get_table_names():
                    Testimonial.__table__.create(bind=db.engine, checkfirst=True)
                    print('✓ Created missing table testimonials')
            except Exception as e:
                print('✗ Failed to ensure testimonials table:', e)

            # Ensure email OTP challenges table exists (hotfix for missing migrations)
            try:
                if 'email_otp_challenges' not in insp.get_table_names():
                    EmailOTPChallenge.__table__.create(bind=db.engine, checkfirst=True)
                    print('✓ Created missing table email_otp_challenges')
            except Exception as e:
                print('✗ Failed to ensure email_otp_challenges table:', e)

            # Ensure partners table exists (hotfix for missing migrations)
            try:
                if 'partners' not in insp.get_table_names():
                    Partner.__table__.create(bind=db.engine, checkfirst=True)
                    print('✓ Created missing table partners')
            except Exception as e:
                print('✗ Failed to ensure partners table:', e)

            # Ensure appointments table has payment columns (hotfix for missing migrations)
            try:
                if 'appointments' in insp.get_table_names():
                    appt_cols = [c['name'] for c in insp.get_columns('appointments')]
                    payment_needed = {
                        'payment_status': "VARCHAR(20) DEFAULT 'unpaid'",
                        'payment_amount': 'FLOAT',
                        'payment_date': 'TIMESTAMP',
                        'payment_method': 'VARCHAR(50)',
                        'reminder_sent_at': 'TIMESTAMP'
                    }
                    for col, coltype in payment_needed.items():
                        if col not in appt_cols:
                            try:
                                with db.engine.begin() as conn:
                                    conn.execute(text(f"ALTER TABLE appointments ADD COLUMN {col} {coltype}"))
                                print(f'✓ Added missing column appointments.{col}')
                            except Exception as e:
                                print(f'✗ Failed to add appointments.{col}:', e)
            except Exception as e:
                print('✗ Failed to inspect appointments table:', e)

            # Ensure communications table has threading/receipt columns (hotfix for missing migrations)
            try:
                if 'communications' in insp.get_table_names():
                    comm_cols = [c['name'] for c in insp.get_columns('communications')]
                    comm_needed = {
                        'reply_to_message_id': 'INTEGER',
                        'thread_root_id': 'INTEGER',
                        'receipt_data': 'TEXT'
                    }
                    for col, coltype in comm_needed.items():
                        if col not in comm_cols:
                            try:
                                with db.engine.begin() as conn:
                                    conn.execute(text(f"ALTER TABLE communications ADD COLUMN {col} {coltype}"))
                                print(f'✓ Added missing column communications.{col}')
                            except Exception as e:
                                print(f'✗ Failed to add communications.{col}:', e)
            except Exception as e:
                print('✗ Failed to inspect communications table:', e)

            # Ensure call_sessions table has required columns (hotfix for CallSession model expansion)
            try:
                if 'call_sessions' in insp.get_table_names():
                    cs_cols = [c['name'] for c in insp.get_columns('call_sessions')]
                    cs_needed = {
                        'call_id': 'VARCHAR(64)',
                        'caller_id': 'INTEGER',
                        'callee_id': 'INTEGER',
                        'call_type': 'VARCHAR(10)',
                        'status': 'VARCHAR(20)',
                        'accepted_at': 'TIMESTAMP',
                        'connected_at': 'TIMESTAMP',
                        'end_reason': 'VARCHAR(30)',
                    }
                    for col, coltype in cs_needed.items():
                        if col not in cs_cols:
                            try:
                                with db.engine.begin() as conn:
                                    conn.execute(text(f"ALTER TABLE call_sessions ADD COLUMN {col} {coltype}"))
                                print(f'✓ Added missing column call_sessions.{col}')
                            except Exception as e:
                                print(f'✗ Failed to add call_sessions.{col}:', e)
            except Exception as e:
                print('✗ Failed to inspect call_sessions table:', e)
            
            # Create default users
            create_default_users()

            try:
                post_bootstrap_user_count = User.query.count()
                print(f"ℹ Startup user count after admin bootstrap: {post_bootstrap_user_count}")
            except Exception as count_error:
                print(f"✗ Unable to count users after bootstrap: {count_error}")
            
        except Exception as e:
            print(f"✗ Database initialization error: {e}")
            import traceback
            traceback.print_exc()

# Run database initialization unless explicitly skipped (useful for quick dev tests)
if os.getenv('SKIP_DB_INIT', '0') != '1':
    initialize_database()

def safe_display_name(user):
    try:
        first = getattr(user, 'first_name', None)
        last = getattr(user, 'last_name', None)
        if first or last:
            return f"{first or ''} {last or ''}".strip()
        return getattr(user, 'username', 'User')
    except Exception:
        return getattr(user, 'username', 'User')


def safe_username(user_or_name):
    try:
        name = user_or_name.username if hasattr(user_or_name, 'username') else str(user_or_name)
        name = name or f'user_{getattr(user_or_name, "id", "unknown")}'
        return secure_filename(name)
    except Exception:
        return f'user_{getattr(user_or_name, "id", "unknown")}'


def current_user_has_role(*roles):
    try:
        if not current_user or not getattr(current_user, 'is_authenticated', False):
            return False
        return getattr(current_user, 'role', None) in set(roles)
    except Exception:
        return False


def parse_bool_flag(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def parse_iso_date(value):
    text_value = (value or '').strip()
    if not text_value:
        return None
    try:
        return datetime.fromisoformat(text_value).date()
    except Exception:
        return None


def parse_optional_float(value):
    text_value = (value or '').strip()
    if not text_value:
        return None
    try:
        return float(text_value)
    except Exception:
        return None


def _extract_receipt_timestamps(message_row):
    received_at = None
    read_at = None
    try:
        raw = getattr(message_row, 'receipt_data', None)
        if raw:
            payload = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(payload, dict):
                received_at = payload.get('received_at') or payload.get('delivered_at')
                read_at = payload.get('read_at')
    except Exception:
        pass
    return received_at, read_at


def _serialize_admin_message_thread(appointment_id):
    rows = Communication.query.filter_by(appointment_id=appointment_id).order_by(Communication.timestamp.asc()).all()
    serialized = []
    for row in rows:
        received_at, read_at = _extract_receipt_timestamps(row)
        sent_at = row.timestamp.isoformat() if getattr(row, 'timestamp', None) else None
        if not received_at and row.is_read and sent_at:
            received_at = sent_at
        serialized.append({
            'id': row.id,
            'appointment_id': row.appointment_id,
            'sender_id': row.sender_id,
            'sender_name': safe_display_name(row.sender) if getattr(row, 'sender', None) else 'Unknown',
            'message_type': row.message_type,
            'content': (row.content or '').strip() if row.content else '',
            'is_read': bool(row.is_read),
            'message_status': row.message_status or ('read' if row.is_read else 'sent'),
            'sent_at': sent_at,
            'received_at': received_at,
            'read_at': read_at,
            'reply_to_message_id': getattr(row, 'reply_to_message_id', None),
            'thread_root_id': getattr(row, 'thread_root_id', None),
        })
    return serialized


def _derive_consultation_lives_summary(consultations):
    summary = {
        'live': 0,
        'ended': 0,
        'rescheduled': 0,
        'missed': 0,
        'total': len(consultations or [])
    }
    for consultation in consultations or []:
        latest_call = consultation.get('latest_call') or {}
        call_status = (latest_call.get('status') or '').strip().lower()
        call_reason = (latest_call.get('end_reason') or '').strip().lower()
        appointment_status = (consultation.get('appointment_status') or '').strip().lower()

        if appointment_status == 'rescheduled':
            summary['rescheduled'] += 1
        if call_status in ('ringing', 'accepted', 'connecting', 'connected'):
            summary['live'] += 1
        elif call_status == 'ended' or appointment_status == 'completed':
            summary['ended'] += 1
        if call_reason in ('missed', 'timeout', 'unanswered', 'declined', 'callee_declined', 'rejected'):
            summary['missed'] += 1
    return summary


def _capture_patient_location_from_request():
    try:
        if not getattr(current_user, 'is_authenticated', False):
            return
        if getattr(current_user, 'role', None) != 'patient':
            return

        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            return

        header_region = (request.headers.get('X-Region') or request.headers.get('X-Client-Region') or '').strip()
        header_city = (request.headers.get('X-City') or request.headers.get('X-Client-City') or '').strip()
        header_country = (request.headers.get('X-Country') or request.headers.get('X-Client-Country') or '').strip()
        header_lat = request.headers.get('X-Latitude')
        header_lng = request.headers.get('X-Longitude')

        dirty = False
        if header_city and not patient.city:
            patient.city = header_city
            dirty = True
        if header_country and not patient.country:
            patient.country = header_country
            dirty = True
        if header_region and not patient.address:
            patient.address = header_region
            dirty = True

        try:
            if header_lat is not None:
                current_user.last_known_lat = float(header_lat)
                dirty = True
            if header_lng is not None:
                current_user.last_known_lng = float(header_lng)
                dirty = True
        except Exception:
            pass

        if dirty:
            db.session.add(patient)
            db.session.add(current_user)
            db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def _table_exists(table_name):
    try:
        return bool(inspect(db.engine).has_table(table_name))
    except Exception:
        return False


# ============================================
# PAYMENT GATING FUNCTIONS
# ============================================

def check_appointment_payment_status(appointment_id, user):
    """Check if user can access messaging for appointment based on payment status"""
    try:
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return False
        
        # Admin can always access
        if user.role == 'admin':
            return True
        
        # Doctor can always access their own appointments
        if user.role == 'doctor' and appointment.doctor_id == user.doctor.id:
            return True
        
        # Patient needs payment
        if user.role == 'patient' and appointment.patient_id == user.patient.id:
            return appointment.payment_status == 'paid'
        
        return False
    except Exception as e:
        print(f'Error checking payment status: {e}')
        return False


def is_patient_payment_locked(appointment_id):
    """Check if patient messaging is locked due to unpaid consultation"""
    try:
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return False
        return appointment.payment_status == 'unpaid'
    except Exception:
        return False


def get_unpaid_patients_for_doctor(doctor_id):
    """Get all patients with unpaid consultations for a specific doctor"""
    try:
        unpaid = db.session.query(Appointment).filter(
            Appointment.doctor_id == doctor_id,
            Appointment.payment_status == 'unpaid',
            Appointment.status.in_(['pending', 'confirmed'])
        ).all()
        return unpaid
    except Exception as e:
        print(f'Error getting unpaid patients: {e}')
        return []


def send_payment_reminder_notification(appointment_id, doctor_id):
    """Send payment reminder notification to patient"""
    try:
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return False
        
        doctor = db.session.get(Doctor, doctor_id)
        if not doctor:
            return False
        
        patient_user = appointment.patient.user
        doctor_name = safe_display_name(doctor.user) if doctor.user else 'Doctor'
        
        # Create notification
        notification = Notification(
            user_id=patient_user.id,
            notification_type='payment_reminder',
            title='Payment Required',
            body=f'{doctor_name} sent you a reminder: Please pay your consultation fee of KES {appointment.payment_amount or "TBD"} to unlock messaging and call features.',
            appointment_id=appointment_id,
            sender_id=doctor.user_id
        )
        db.session.add(notification)
        appointment.send_payment_reminder()
        
        # Emit Socket.IO event to patient if online
        try:
            if _is_user_online(patient_user.id):
                _emit_to_user(patient_user.id, 'payment_reminder', {
                    'appointment_id': appointment_id,
                    'doctor_name': doctor_name,
                    'amount': appointment.payment_amount or 'TBD',
                    'message': f'Your consultation with {doctor_name} requires payment before proceeding.'
                })
        except Exception as e:
            print(f'Error emitting payment reminder socket: {e}')
        
        return True
    except Exception as e:
        db.session.rollback()
        print(f'Error sending payment reminder: {e}')
        return False


# ----------------------
# Socket.IO call handlers
# ----------------------
from flask import copy_current_request_context


def _insert_call_event_message(appointment_id, caller_id, callee_id, call_type, event, duration=None):
    """Insert a system message into the chat for call events (missed, completed, etc.)."""
    try:
        if not appointment_id:
            return
        icons = {'missed': '📵', 'completed': '📞', 'declined': '📵', 'connection_failed': '📵', 'busy': '📵'}
        icon = icons.get(event, '📞')
        labels = {
            'missed': 'Missed voice call' if call_type == 'voice' else 'Missed video call',
            'completed': f'{"Voice" if call_type == "voice" else "Video"} call ended',
            'declined': f'{"Voice" if call_type == "voice" else "Video"} call declined',
            'connection_failed': f'{"Voice" if call_type == "voice" else "Video"} call failed',
            'busy': f'{"Voice" if call_type == "voice" else "Video"} call — user busy',
        }
        label = labels.get(event, f'{call_type.title()} call')
        dur_str = ''
        if duration and duration > 0:
            m, s = divmod(int(duration), 60)
            dur_str = f' ({m}m {s}s)' if m else f' ({s}s)'
        content = f'{icon} {label}{dur_str}'
        comm = Communication(
            appointment_id=int(appointment_id),
            sender_id=int(caller_id),
            message_type='system',
            content=content,
            timestamp=now_eat(),
            is_read=False,
            message_status='sent'
        )
        db.session.add(comm)
        db.session.commit()
        # Broadcast to both users so it appears in chat
        msg_data = {
            'id': comm.id,
            'appointment_id': int(appointment_id),
            'sender_id': int(caller_id),
            'message_type': 'system',
            'content': content,
            'timestamp': now_eat().isoformat(),
            'is_read': False,
        }
        socketio.emit('new_message', msg_data, room=f'appointment_{appointment_id}')
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def find_active_call(call_id=None, appointment_id=None):
    """
    Helper to find an active call by call_id or appointment_id.
    Returns (key, call_info) where key is the dict key in active_calls.
    """
    if call_id:
        if call_id in active_calls:
            return call_id, active_calls[call_id]
    if appointment_id:
        if appointment_id in active_calls:
            return appointment_id, active_calls[appointment_id]
    for key, value in active_calls.items():
        if call_id and value.get('id') == call_id:
            return key, value
        if appointment_id and value.get('appointment_id') == appointment_id:
            return key, value
    try:
        if call_id:
            cached = _redis_get_json(f'active_call:{call_id}')
            if cached:
                active_calls[call_id] = cached
                return call_id, cached
        if appointment_id:
            cached = _redis_get_json(f'active_call:appointment:{appointment_id}')
            if cached:
                active_calls[appointment_id] = cached
                return appointment_id, cached
    except Exception:
        pass
    return None, None


def _record_call_history(
    call_id,
    appointment_id=None,
    caller_id=None,
    callee_id=None,
    call_type='video',
    status=None,
    initiated_at=None,
    ringing_at=None,
    accepted_at=None,
    connected_at=None,
    ended_at=None,
    end_reason=None,
    duration=None,
    room_id=None,
    sfu_server=None,
    participants_count=None,
    recording_url=None,
    recording_duration=None,
    recording_consent=None,
):
    """Create or update CallHistory rows for call state transitions."""
    try:
        if not call_id:
            return None
        try:
            if appointment_id is not None:
                appointment_id = int(appointment_id)
        except Exception:
            pass
        try:
            if caller_id is not None:
                caller_id = int(caller_id)
        except Exception:
            pass
        try:
            if callee_id is not None:
                callee_id = int(callee_id)
        except Exception:
            pass

        call = CallHistory.query.filter_by(call_id=str(call_id)).first()
        now = now_eat()
        if not call:
            call = CallHistory(
                call_id=str(call_id),
                appointment_id=appointment_id,
                caller_id=caller_id,
                callee_id=callee_id,
                call_type=call_type,
                initiated_at=initiated_at or now,
                status=status or 'initiated'
            )
            db.session.add(call)

        if appointment_id is not None:
            call.appointment_id = appointment_id
        if caller_id is not None:
            call.caller_id = caller_id
        if callee_id is not None:
            call.callee_id = callee_id
        if call_type:
            call.call_type = call_type
        if status:
            call.status = status
        if initiated_at is not None:
            call.initiated_at = initiated_at
        if ringing_at is not None:
            call.ringing_at = ringing_at
        if accepted_at is not None:
            call.accepted_at = accepted_at
        if connected_at is not None:
            call.connected_at = connected_at
        if ended_at is not None:
            call.ended_at = ended_at
        if end_reason is not None:
            call.end_reason = end_reason
        if duration is not None:
            call.duration = duration
        if room_id is not None:
            call.room_id = room_id
        if sfu_server is not None and hasattr(call, 'sfu_server'):
            call.sfu_server = sfu_server
        if participants_count is not None and hasattr(call, 'participants_count'):
            call.participants_count = participants_count
        if recording_url is not None and hasattr(call, 'recording_url'):
            call.recording_url = recording_url
        if recording_duration is not None and hasattr(call, 'recording_duration'):
            call.recording_duration = recording_duration
        if recording_consent is not None and hasattr(call, 'recording_consent'):
            call.recording_consent = bool(recording_consent)
        db.session.commit()
        return call
    except Exception:
        db.session.rollback()
        return None


def _update_call_session(
    call_id,
    appointment_id=None,
    caller_id=None,
    callee_id=None,
    call_type='video',
    status=None,
    started_at=None,
    accepted_at=None,
    connected_at=None,
    ended_at=None,
    duration_seconds=None,
    end_reason=None,
    participants=None,
    call_quality=None,
):
    """Create or update the active CallSession row for a call."""
    try:
        if not call_id and not appointment_id:
            return None
        session_row = None
        if hasattr(CallSession, 'call_id') and call_id:
            session_row = CallSession.query.filter_by(call_id=str(call_id)).first()
        if not session_row and appointment_id is not None:
            session_row = CallSession.query.filter_by(appointment_id=appointment_id, ended_at=None).order_by(CallSession.started_at.desc()).first()
        if not session_row:
            session_kwargs = {}
            if hasattr(CallSession, 'call_id') and call_id:
                session_kwargs['call_id'] = str(call_id)
            if appointment_id is not None:
                session_kwargs['appointment_id'] = appointment_id
            session_row = CallSession(**session_kwargs)
            db.session.add(session_row)
        if appointment_id is not None:
            session_row.appointment_id = appointment_id
        if caller_id is not None and hasattr(session_row, 'caller_id'):
            session_row.caller_id = caller_id
        if callee_id is not None and hasattr(session_row, 'callee_id'):
            session_row.callee_id = callee_id
        if call_type and hasattr(session_row, 'call_type'):
            session_row.call_type = call_type
        if status and hasattr(session_row, 'status'):
            session_row.status = status
        if started_at is not None:
            session_row.started_at = started_at
        if accepted_at is not None and hasattr(session_row, 'accepted_at'):
            session_row.accepted_at = accepted_at
        if connected_at is not None and hasattr(session_row, 'connected_at'):
            session_row.connected_at = connected_at
        if ended_at is not None:
            session_row.ended_at = ended_at
        if duration_seconds is not None and hasattr(session_row, 'duration_seconds'):
            session_row.duration_seconds = duration_seconds
        elif duration_seconds is not None and hasattr(session_row, 'duration'):
            session_row.duration = duration_seconds
        if end_reason is not None and hasattr(session_row, 'end_reason'):
            session_row.end_reason = end_reason
        if participants is not None and hasattr(session_row, 'participants'):
            session_row.participants = participants
        if call_quality is not None and hasattr(session_row, 'call_quality'):
            session_row.call_quality = call_quality
        db.session.commit()
        return session_row
    except Exception:
        db.session.rollback()
        return None


@socketio.on('register_user')
def handle_register_user(data):
    """Register a connected socket for a user: {user_id}"""
    if not current_user or not current_user.is_authenticated:
        emit('registered', {'status': 'error', 'error': 'not_authenticated'})
        return False
    try:
        uid = int((data or {}).get('user_id'))
    except Exception:
        emit('registered', {'status': 'error', 'error': 'invalid_user'})
        return False

    if uid != int(current_user.id):
        emit('registered', {'status': 'error', 'error': 'user_mismatch'})
        return False

    sid = request.sid
    _add_user_socket(uid, sid)
    user_last_seen[uid] = now_eat()
    join_room(f'user_{uid}')
    join_room(f'role_{current_user.role}')
    if current_user.role == 'admin':
        join_room('admins')
    _set_presence(uid, online=True)
    _metric_incr('connections', 1)
    emit('registered', {'status': 'ok', 'user_id': uid})
    _log_event('socket_register', user_id=uid, sid=request.sid)
    return True


@socketio.on('heartbeat')
def handle_heartbeat(data):
    """Keep presence fresh and accept optional client-side call quality stats."""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        user_id = current_user.id
        user_last_seen[user_id] = now_eat()
        _set_presence(user_id, online=True)

        quality_score = (data or {}).get('call_quality_score', 0)
        latency = (data or {}).get('latency_ms', 0)
        packet_loss = (data or {}).get('packet_loss_pct', 0)

        if quality_score < 50 or latency > 500 or packet_loss > 10:
            try:
                app.logger.warning(
                    f'Poor call quality user_id={user_id}: '
                    f'quality={quality_score}% latency={latency}ms loss={packet_loss}%'
                )
            except Exception:
                pass

        emit('heartbeat_ack', {
            'server_time': now_eat().isoformat(),
            'status': 'ok'
        })
    except Exception as e:
        app.logger.debug(f'Heartbeat error: {e}')


@socketio.on('call_quality_metric')
def handle_call_quality_metric(data):
    """Receive and log call quality metrics from client for monitoring/analysis
    Data: {appointment_id, bitrate, packets_lost, packet_loss_pct, round_trip_time_ms, jitter_ms}
    """
    try:
        appointment_id = data.get('appointment_id')
        bitrate = data.get('available_outgoing_bitrate', 0)
        packet_loss = data.get('packet_loss', 0)
        rtt = data.get('roundTripTime', 0)
        
        # Log metrics that indicate problems
        if bitrate < 250000 or packet_loss > 0.05:
            app.logger.info(
                f'Call quality: apt={appointment_id} '
                f'bitrate={bitrate}bps packet_loss={packet_loss*100:.1f}% rtt={rtt*1000:.0f}ms'
            )
    except Exception as e:
        app.logger.debug(f'Quality metric error: {e}')


def _emit_to_user(user_id, event, payload):
    # emit to personal room
    try:
        socketio.emit(event, payload, room=f'user_{user_id}')
    except Exception:
        pass


def _call_participant_ids(call_info=None, include_observers=True, connected_only=False):
    participants = []
    if not isinstance(call_info, dict):
        return participants

    for participant in call_info.get('participants') or []:
        if not isinstance(participant, dict):
            continue
        if not include_observers and participant.get('mode') == 'observer':
            continue
        if connected_only and not participant.get('joined'):
            continue
        try:
            user_id = int(participant.get('user_id'))
        except Exception:
            continue
        if user_id not in participants:
            participants.append(user_id)

    if participants:
        return participants

    for key in ('caller', 'caller_id', 'callee', 'callee_id'):
        value = call_info.get(key)
        if value is None:
            continue
        try:
            value = int(value)
        except Exception:
            continue
        if value not in participants:
            participants.append(value)
    return participants


def _emit_call_event(call_info, event, payload=None):
    payload = payload or {}
    for user_id in _call_participant_ids(call_info, include_observers=False):
        _emit_to_user(user_id, event, payload)


def _call_event_payload(call_info, stage=None, extra=None):
    payload = {
        'call_id': call_info.get('id') or call_info.get('call_id'),
        'appointment_id': call_info.get('appointment_id'),
        'call_type': call_info.get('call_type', 'video'),
        'caller_id': call_info.get('caller') or call_info.get('caller_id'),
        'callee_id': call_info.get('callee') or call_info.get('callee_id'),
        'caller_name': call_info.get('caller_name'),
        'callee_name': call_info.get('callee_name'),
        'status': stage or call_info.get('status'),
        'reason': call_info.get('end_reason'),
        'timestamp': now_eat().isoformat(),
        'participants': call_info.get('participants') or [],
        'participants_count': call_info.get('participants_count') or len(_call_participant_ids(call_info, include_observers=False)),
        'observer_count': call_info.get('observer_count') or len([p for p in call_info.get('participants') or [] if p.get('mode') == 'observer']),
        'room_id': call_info.get('room_id'),
        'media_topology': call_info.get('media_topology') or _get_call_media_topology(),
        'sfu_server': call_info.get('sfu_server') or _get_call_sfu_server(),
        'auto_record': bool(call_info.get('auto_record', True)),
        'recording_state': call_info.get('recording_state') or 'armed'
    }
    if extra:
        payload.update(extra)
    return payload


def _emit_admin_call_event(payload):
    try:
        socketio.emit('admin:call_event', payload, room='admins')
    except Exception:
        pass


def _emit_call_lifecycle(call_info, stage, extra=None, legacy_events=None):
    payload = _call_event_payload(call_info, stage=stage, extra=extra)
    stage_events = {
        'initiate': ['call:initiate'],
        'ringing': ['call:ringing'],
        'accept': ['call:accept', 'call:accepted'],
        'connected': ['call:connected'],
        'reject': ['call:reject', 'call:declined'],
        'missed': ['call:missed'],
        'busy': ['call:busy'],
        'failed': ['call:failed'],
        'ended': ['call:ended']
    }
    for event_name in stage_events.get(stage, [f'call:{stage}']):
        _emit_call_event(call_info, event_name, payload)
    for event_name in legacy_events or []:
        _emit_call_event(call_info, event_name, payload)
    _emit_admin_call_event(payload)
    return payload


def _set_appointment_call_status(appointment_id, status, initiated_by=None):
    try:
        if not appointment_id:
            return
        appointment = db.session.get(Appointment, int(appointment_id))
        if not appointment:
            return
        appointment.call_status = status
        if initiated_by is not None:
            appointment.call_initiated_by = initiated_by
        db.session.commit()
    except Exception:
        db.session.rollback()


def _resolve_call_type(call_id=None, appointment_id=None, data=None, default='video'):
    try:
        if isinstance(data, dict):
            explicit_type = data.get('call_type')
            if explicit_type in ('voice', 'video'):
                return explicit_type
        _, call_info = find_active_call(call_id=call_id, appointment_id=appointment_id)
        if call_info and call_info.get('call_type') in ('voice', 'video'):
            return call_info.get('call_type')
        if call_id:
            call_history = CallHistory.query.filter_by(call_id=str(call_id)).first()
            if call_history and call_history.call_type in ('voice', 'video'):
                return call_history.call_type
    except Exception:
        pass
    return default


# SQLAlchemy event listener: when a Notification row is inserted, emit a Socket.IO 'notification' event
def _on_notification_insert(mapper, connection, target):
    try:
        payload = {
            'id': target.id,
            'type': target.notification_type,
            'title': target.title,
            'body': target.body,
            'sender_id': target.sender_id,
            'appointment_id': target.appointment_id,
            'is_read': target.is_read,
            'created_at': target.created_at.isoformat() if getattr(target, 'created_at', None) else None
        }
        # Emit to the user's personal room so connected browsers get the notification in real-time
        try:
            socketio.emit('notification', payload, room=f'user_{target.user_id}')
            # Also emit an unread_count event so clients can update badge cheaply
            try:
                unread = Notification.query.filter_by(user_id=target.user_id, is_read=False).count()
                socketio.emit('unread_count', {'unread_count': unread}, room=f'user_{target.user_id}')
            except Exception:
                # best-effort: if counting fails, ignore
                pass
        except Exception:
            pass
    except Exception:
        pass

# Register the listener
try:
    sqlalchemy_event.listen(Notification, 'after_insert', _on_notification_insert)
except Exception:
    # If Notification isn't available yet or registration fails, ignore gracefully
    pass


# -------------------------
# Web Push helpers and endpoints
# -------------------------
def _load_push_subscriptions():
    try:
        if _PUSH_SUB_FILE.exists():
            with _PUSH_SUB_FILE.open('r', encoding='utf-8') as fh:
                data = _json.load(fh)
                if isinstance(data, dict):
                    push_subscriptions.clear()
                    for k, v in data.items():
                        push_subscriptions[int(k)] = v
    except Exception:
        pass

def _save_push_subscriptions():
    try:
        # persist mapping of user_id -> [subscription,...]
        dump = {str(k): v for k, v in push_subscriptions.items()}
        with _PUSH_SUB_FILE.open('w', encoding='utf-8') as fh:
            _json.dump(dump, fh)
    except Exception:
        pass

# Load existing subscriptions at startup (best-effort)
try:
    _load_push_subscriptions()
except Exception:
    pass


@app.route('/api/ice', methods=['GET'])
@login_required
def get_ice():
    """Return current ICE server config without hard-coding secrets in clients.
    In production, implement rotation for TURN creds and fetch here.
    """
    # Basic ETag to help cache for a short time but rotate if env changes
    try:
        from hashlib import sha256
        key = sha256((os.getenv('TURN_USER','') + '|' + os.getenv('TURN_URLS','') + '|' + os.getenv('TURN_PASS','')).encode()).hexdigest()
    except Exception:
        key = None
    resp = jsonify({'iceServers': app.config.get('ICE_SERVERS', [])})
    if key:
        resp.headers['ETag'] = key
    resp.headers['Cache-Control'] = 'private, max-age=120'
    return resp


@app.route('/api/ice/diagnostics', methods=['GET'])
@login_required
def get_ice_diagnostics():
    """Return safe TURN/STUN diagnostics without exposing credentials."""
    try:
        servers = app.config.get('ICE_SERVERS', [])
        sanitized = []
        has_turn = False
        for server in servers:
            urls = server.get('urls') if isinstance(server, dict) else None
            if isinstance(urls, str):
                urls = [urls]
            urls = urls or []
            if any(str(u).startswith('turn:') or str(u).startswith('turns:') for u in urls):
                has_turn = True
            sanitized.append({
                'urls': urls,
                'has_auth': bool((server or {}).get('username') or (server or {}).get('credential'))
            })

        return jsonify({'success': True, 'data': {'has_turn': has_turn, 'servers': sanitized}})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/call-media-config/<int:appointment_id>', methods=['GET'])
@login_required
def get_call_media_config(appointment_id):
    """Return public call media topology config for the appointment call room."""
    appointment = _socket_get_appointment(appointment_id, error_event='call_error', require_payment=False)
    if not appointment:
        return jsonify({'success': False, 'error': 'access_denied'}), 403
    requested_call_type = (request.args.get('call_type') or '').strip().lower()
    if requested_call_type not in ('voice', 'video'):
        requested_call_type = None
    requested_call_id = (request.args.get('call_id') or '').strip() or None
    _, call_info = find_active_call(call_id=requested_call_id, appointment_id=appointment_id)
    call_type = requested_call_type or (call_info or {}).get('call_type', 'video')
    room_id = _resolve_call_room(
        appointment_id=appointment_id,
        call_id=requested_call_id or (call_info or {}).get('id') or (call_info or {}).get('call_id'),
        call_type=call_type,
    )
    config = _get_public_media_bridge_config(call_info)
    config.update({
        'appointment_id': appointment_id,
        'call_type': call_type,
        'room_id': room_id,
        'participant_ids': _room_member_ids(room_id),
        'session': _build_media_bridge_session(
            room_id,
            appointment_id=appointment_id,
            call_info=call_info,
            call_type=call_type,
            user=current_user,
        ),
    })
    return jsonify({'success': True, 'config': config})

@app.route('/api/push/vapid_public_key', methods=['GET'])
def vapid_public_key():
    """Return VAPID public key (base64url) for client subscription.
    The server must be configured with VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY environment variables.
    """
    pub = os.getenv('VAPID_PUBLIC_KEY')
    if not pub:
        return jsonify({'success': False, 'error': 'VAPID keys not configured on server'}), 500
    return jsonify({'success': True, 'vapid_public_key': pub})


@app.route('/api/push/subscribe', methods=['POST'])
def push_subscribe():
    try:
        payload = request.get_json(force=True)
    except Exception:
        payload = None
    if not payload:
        return jsonify({'success': False, 'error': 'invalid_payload'}), 400
    subscription = payload.get('subscription') or payload.get('sub')
    # prefer logged in user if available
    uid = None
    try:
        if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            uid = int(getattr(current_user, 'id'))
    except Exception:
        uid = None
    if not uid:
        # fallback to supplied user_id
        try:
            uid = int(payload.get('user_id'))
        except Exception:
            return jsonify({'success': False, 'error': 'missing_user_id'}), 400
    if not subscription or not isinstance(subscription, dict):
        return jsonify({'success': False, 'error': 'invalid_subscription'}), 400

    # Persist to DB when available
    try:
        if 'db' in globals():
            # Upsert by endpoint
            ep = subscription.get('endpoint')
            existing = None
            try:
                existing = PushSubscription.query.filter_by(endpoint=ep).first() if ep else None
            except Exception:
                existing = None
            if existing:
                existing.keys = subscription.get('keys') or subscription.get('keys', {})
                existing.raw = subscription
                existing.is_active = True
                try:
                    existing.user_agent = request.headers.get('User-Agent')
                except Exception:
                    pass
                db.session.add(existing)
                db.session.commit()
            else:
                try:
                    ps = PushSubscription(user_id=uid, endpoint=ep or '', keys=subscription.get('keys') or {}, raw=subscription, user_agent=request.headers.get('User-Agent'))
                    db.session.add(ps)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
    except Exception:
        pass

    # Keep file-backed store as best-effort cache as well
    lst = push_subscriptions.get(uid) or []
    endpoint = subscription.get('endpoint')
    if not any(s.get('endpoint') == endpoint for s in lst):
        lst.append(subscription)
    push_subscriptions[uid] = lst
    _save_push_subscriptions()
    return jsonify({'success': True})


@app.route('/api/push/unsubscribe', methods=['POST'])
def push_unsubscribe():
    try:
        payload = request.get_json(force=True)
    except Exception:
        payload = None
    if not payload:
        return jsonify({'success': False, 'error': 'invalid_payload'}), 400
    subscription = payload.get('subscription') or payload.get('sub')
    uid = None
    try:
        if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            uid = int(getattr(current_user, 'id'))
    except Exception:
        uid = None
    if not uid:
        try:
            uid = int(payload.get('user_id'))
        except Exception:
            return jsonify({'success': False, 'error': 'missing_user_id'}), 400
    if not subscription:
        return jsonify({'success': False, 'error': 'invalid_subscription'}), 400
    # Remove from DB when available
    try:
        if 'db' in globals():
            ep = subscription.get('endpoint')
            try:
                PushSubscription.query.filter_by(endpoint=ep).delete()
                db.session.commit()
            except Exception:
                db.session.rollback()
    except Exception:
        pass

    # Remove from file-backed store as well
    lst = push_subscriptions.get(uid) or []
    endpoint = subscription.get('endpoint')
    lst = [s for s in lst if s.get('endpoint') != endpoint]
    if lst:
        push_subscriptions[uid] = lst
    else:
        push_subscriptions.pop(uid, None)
    _save_push_subscriptions()
    return jsonify({'success': True})


def _send_push_to_subscription(subscription, payload):
    """Send a push message using pywebpush. Returns True on success, False otherwise."""
    vapid_private = os.getenv('VAPID_PRIVATE_KEY')
    vapid_email = os.getenv('VAPID_CLAIMS_SUB', 'mailto:admin@makokhamedical.com')
    if not vapid_private:
        raise RuntimeError('VAPID_PRIVATE_KEY not set')
    try:
        webpush(
            subscription_info=subscription,
            data=_json.dumps(payload),
            vapid_private_key=vapid_private,
            vapid_claims={"sub": vapid_email}
        )
        return True
    except WebPushException as ex:
        # If subscription is no longer valid, caller should remove it
        app.logger.warning('WebPush failed: %s', str(ex))
        return False
    except Exception as e:
        app.logger.exception('Unexpected error sending webpush: %s', e)
        return False


@app.route('/api/push/send', methods=['POST'])
def push_send():
    """Send a push notification to a user or test payload.
    JSON body: { user_id: <int>, payload: { title, body, url, ... } }
    If user_id omitted and current user is provided or request contains 'to_all': send accordingly.
    """
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}
    target_user = data.get('user_id')
    payload = data.get('payload') or {'title': data.get('title', 'Notification'), 'body': data.get('body', ''), 'url': data.get('url', '/')}
    if not target_user:
        # allow sending to current user for testing
        try:
            if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
                target_user = int(getattr(current_user, 'id'))
        except Exception:
            target_user = None
    if not target_user:
        return jsonify({'success': False, 'error': 'missing_user_id'}), 400

    # Prefer DB-backed subscriptions if model exists
    subs = []
    try:
        if 'PushSubscription' in globals():
            subs_q = PushSubscription.query.filter_by(user_id=int(target_user), is_active=True).all()
            subs = [s.raw for s in subs_q if getattr(s, 'raw', None)]
    except Exception:
        subs = push_subscriptions.get(int(target_user)) or []
    successes = 0
    to_remove = []
    for s in list(subs):
        ok = _send_push_to_subscription(s, payload)
        if ok:
            successes += 1
        else:
            # schedule to remove invalid subscription
            if s.get('endpoint'):
                to_remove.append(s.get('endpoint'))
    if to_remove:
        subs = [x for x in subs if x.get('endpoint') not in to_remove]
        if subs:
            push_subscriptions[int(target_user)] = subs
        else:
            push_subscriptions.pop(int(target_user), None)
        _save_push_subscriptions()

    return jsonify({'success': True, 'sent': successes})



def _uploads_rel_root():
    """Return uploads root relative to `static` (e.g. 'uploads')."""
    rel = app.config.get('UPLOAD_FOLDER', 'static/uploads').replace('\\', '/')
    if rel.startswith('static/'):
        return rel[len('static/'):]
    if rel == 'static':
        return ''
    return rel


def resolve_stored_path(stored_path):
    """Resolve stored_path to absolute filesystem path. For external URLs, returns the URL string unchanged."""
    if not stored_path:
        return None
    if isinstance(stored_path, str) and stored_path.startswith('http'):
        return stored_path
    if os.path.isabs(stored_path):
        return stored_path
    # assume relative to app.root_path
    return os.path.join(app.root_path, stored_path)


google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    scope=["profile", "email"],
    # Do not pass `current_user` at import time — use storage without binding a user
    storage=SQLAlchemyStorage(SocialAccount, db.session)
)

facebook_bp = make_facebook_blueprint(
    client_id=app.config['FACEBOOK_OAUTH_CLIENT_ID'],
    client_secret=app.config['FACEBOOK_OAUTH_CLIENT_SECRET'],
    scope=["email", "public_profile"],
    # Do not pass `current_user` at import time — use storage without binding a user
    storage=SQLAlchemyStorage(SocialAccount, db.session)
)

twitter_bp = None

# Register available OAuth blueprints
app.register_blueprint(google_bp, url_prefix="/login")
app.register_blueprint(facebook_bp, url_prefix="/login")

# Register communication blueprint
from api.communication import communication_bp
app.register_blueprint(communication_bp)

# Register messaging blueprint (new real-time chat system)
from api.messaging import messaging_bp, init_messaging
csrf.exempt(messaging_bp)  # Messaging API uses session auth; CSRF exempt for JSON endpoints
app.register_blueprint(messaging_bp)
init_messaging(socketio, csrf, _get_redis_client, user_sockets, rate_limits, idempotency_cache)

# Register versioned API blueprint
try:
    from api.v1 import v1_bp
    app.register_blueprint(v1_bp)
    print("✓ Registered /api/v1 blueprint")
except Exception as e:
    print(f"✗ Failed to register /api/v1 blueprint: {e}")

def cleanup_old_sessions():
    """Clean up old user sessions"""
    cutoff_time = now_eat() - timedelta(hours=1)
    users_to_remove = []
    
    for user_id, last_seen_str in list(user_last_seen.items()):
        try:
            last_seen = datetime.fromisoformat(last_seen_str)
            if last_seen < cutoff_time:
                users_to_remove.append(user_id)
        except:
            pass
    
    for user_id in users_to_remove:
        _set_user_sockets(user_id, [])
        if user_id in user_last_seen:
            del user_last_seen[user_id]
    
    # Force garbage collection
    gc.collect()

# Schedule cleanup (run every hour)
import threading
def schedule_cleanup():
    while True:
        try:
            # Run the cleanup in an application context so any DB or app resources
            # referenced by cleanup_old_sessions are available.
            with app.app_context():
                app.logger.debug('schedule_cleanup: running cleanup_old_sessions')
                try:
                    cleanup_old_sessions()
                    app.logger.debug('schedule_cleanup: completed cleanup_old_sessions')
                except Exception as e:
                    app.logger.exception('schedule_cleanup: cleanup_old_sessions error: %s', e)
                try:
                    dispatch_day_of_appointment_reminders()
                except Exception as e:
                    app.logger.exception('schedule_cleanup: day-of reminder dispatch error: %s', e)
                try:
                    dispatch_appointment_outcome_emails()
                except Exception as e:
                    app.logger.exception('schedule_cleanup: outcome email dispatch error: %s', e)
        except Exception as e:
            # Log outer exceptions but keep the loop alive
            try:
                app.logger.exception('schedule_cleanup: unexpected error: %s', e)
            except Exception:
                print(f'schedule_cleanup unexpected error: {e}')
        # Wait 1 hour before next run
        threading.Event().wait(3600)  # Wait 1 hour


# Prescription expiry worker: marks prescriptions expired when expiry_date is reached
def prescription_expiry_worker(interval_seconds=600):
    from time import sleep
    while True:
        try:
            with app.app_context():
                now = now_eat()
                expiring = Prescription.query.filter(Prescription.expiry_date != None, Prescription.expiry_date < now, Prescription.is_expired == False).all()
                for p in expiring:
                    p.is_expired = True
                    try:
                        audit = PrescriptionAudit(prescription_id=p.id, user_id=None, action='auto_expired', extra_info='expiry_date passed')
                        db.session.add(audit)
                    except Exception:
                        db.session.rollback()
                if expiring:
                    db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
        sleep(interval_seconds)


def start_background_workers():
    try:
        t = threading.Thread(target=prescription_expiry_worker, kwargs={'interval_seconds':600}, daemon=True, name='prescription_expiry_worker')
        t.start()
        app.logger.info('Started background thread: prescription_expiry_worker')
    except Exception as e:
        try:
            app.logger.exception('Failed to start prescription_expiry_worker: %s', e)
        except Exception:
            print(f'Failed to start prescription_expiry_worker: {e}')

# Start background workers when app initializes (best-effort)
try:
    start_background_workers()
except Exception:
    pass

# Social authentication success handler
@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", category="error")
        return False

    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", category="error")
        return False

    google_info = resp.json()
    google_user_id = google_info["id"]

    # Find this OAuth token in the database, or create it
    query = SocialAccount.query.filter_by(
        provider=blueprint.name,
        provider_user_id=google_user_id,
    )
    try:
        social_account = query.one()
    except NoResultFound:
        social_account = SocialAccount(
            provider=blueprint.name,
            provider_user_id=google_user_id,
            access_token=token["access_token"],
        )

    if social_account.user:
        login_user(social_account.user)
        flash("Successfully signed in with Google.", "success")
    else:
        # Create a new user
        user = User(
            username=google_info["email"].split('@')[0],
            email=google_info["email"],
            first_name=google_info.get("given_name", ""),
            last_name=google_info.get("family_name", ""),
            role='patient'
        )
        # Generate a random password for social login users
        user.set_password(os.urandom(24).hex())
        
        # Create user profile picture from Google
        if google_info.get("picture"):
            user.profile_picture = google_info["picture"]

        # Add the user to the database
        db.session.add(user)
        db.session.commit()

        # Create patient profile for newly signed-up users
        try:
            patient = Patient(user_id=user.id)
            db.session.add(patient)
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Link social account to user
        social_account.user = user
        db.session.add(social_account)
        db.session.commit()

        # Create patient profile
        patient = Patient(user_id=user.id)
        db.session.add(patient)
        synced_patient = _sync_patient_picture_from_user(user)
        if synced_patient:
            db.session.add(synced_patient)
        db.session.commit()

        # Log in the new user
        login_user(user)
        flash("Successfully signed up with Google!", "success")

    # Disable Flask-Dance's default behavior for saving the OAuth token
    return False

@oauth_authorized.connect_via(facebook_bp)
def facebook_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Facebook.", category="error")
        return False

    resp = blueprint.session.get("/me?fields=id,email,first_name,last_name,picture")
    if not resp.ok:
        flash("Failed to fetch user info from Facebook.", category="error")
        return False

    facebook_info = resp.json()
    facebook_user_id = facebook_info["id"]

    query = SocialAccount.query.filter_by(
        provider=blueprint.name,
        provider_user_id=facebook_user_id,
    )
    try:
        social_account = query.one()
    except NoResultFound:
        social_account = SocialAccount(
            provider=blueprint.name,
            provider_user_id=facebook_user_id,
            access_token=token["access_token"],
        )

    if social_account.user:
        login_user(social_account.user)
        flash("Successfully signed in with Facebook.", "success")
    else:
        # Create username from email or use a generated one
        username = facebook_info.get("email", "").split('@')[0] if facebook_info.get("email") else f"fb_{facebook_user_id}"
        
        user = User(
            username=username,
            email=facebook_info.get("email", f"{facebook_user_id}@facebook.com"),
            first_name=facebook_info.get("first_name", ""),
            last_name=facebook_info.get("last_name", ""),
            role='patient'
        )
        user.set_password(os.urandom(24).hex())
        
        # Add profile picture from Facebook
        if facebook_info.get("picture", {}).get("data", {}).get("url"):
            user.profile_picture = facebook_info["picture"]["data"]["url"]

        db.session.add(user)
        db.session.commit()

        social_account.user = user
        db.session.add(social_account)
        db.session.commit()

        # Create patient profile
        patient = Patient(user_id=user.id)
        db.session.add(patient)
        synced_patient = _sync_patient_picture_from_user(user)
        if synced_patient:
            db.session.add(synced_patient)
        db.session.commit()

        # Log in the new user
        login_user(user)
        flash("Successfully signed up with Facebook!", "success")

# Twitter OAuth handlers removed.

# Handle OAuth errors
@oauth_error.connect
def auth_error(blueprint, error, error_description=None, error_uri=None):
    msg = f"OAuth error from {blueprint.name}: {error}"
    if error_description:
        msg += f" ({error_description})"
    if error_uri:
        msg += f" ({error_uri})"
    flash(msg, "error")

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

def generate_csrf_token():
    """Generate CSRF token"""
    if hasattr(g, 'csrf_token'):
        return g.csrf_token
    token = generate_csrf()
    g.csrf_token = token
    return token

# Make CSRF token available to all templates
@app.context_processor
def inject_csrf_token():
    """Inject CSRF token into template context"""
    return {
        'csrf_token': generate_csrf_token,
        'now': now_eat().date()
    }


def _get_site_content_dict():
    """Load all SiteContent rows into a nested dict: site['section']['key'] = value."""
    import json as _json
    result = {}
    try:
        rows = SiteContent.query.all()
        for row in rows:
            sec = result.setdefault(row.section, {})
            if row.content_type == 'json' and row.value:
                try:
                    sec[row.key] = _json.loads(row.value)
                except Exception:
                    sec[row.key] = row.value
            else:
                sec[row.key] = row.value or ''
    except Exception:
        pass
    return result


def _get_consultation_settings():
    """Return consultation room timing settings from SiteContent.
    Keys: open_before_minutes (int), open_after_minutes (int). 0 = no limit."""
    try:
        rows = SiteContent.query.filter_by(section='consultation_settings').all()
        settings = {}
        for row in rows:
            try:
                settings[row.key] = int(row.value)
            except (ValueError, TypeError):
                settings[row.key] = 0
        return settings
    except Exception:
        return {'open_before_minutes': 0, 'open_after_minutes': 0}


@app.context_processor
def inject_site_content():
    """Make site content available to all templates as `site`."""
    return {'site': _get_site_content_dict()}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def handle_file_upload(user, file_obj, upload_type='profile_pics', encrypt=True):
    """
    Unified secure upload handler with validation, MIME sniffing, UUID storage, and encryption.
    - Validates extension and inspects first bytes for content type
    - Stores outside static/ path where possible, and never serves directly
    - Uses UUID-based filenames; normalizes original name
    - Returns relative path under configured UPLOAD_FOLDER for DB storage
    """
    if not file_obj or not file_obj.filename:
        return None

    # Normalize filename and validate extension
    original = secure_filename(file_obj.filename)
    if not allowed_file(original):
        return None

    # Read a limited buffer for MIME sniffing
    try:
        head = file_obj.stream.read(4096)
        file_obj.stream.seek(0)
    except Exception:
        head = b''

    import mimetypes
    guessed = file_obj.mimetype or mimetypes.guess_type(original)[0] or 'application/octet-stream'

    # Basic server-side content sniffing checks for common types
    def looks_like_image(buf):
        sigs = [b'\xFF\xD8\xFF', b'PNG', b'GIF8', b'RIFF']
        return any(sig in buf[:16] for sig in sigs)
    def looks_like_pdf(buf):
        return buf.startswith(b'%PDF')

    ext = (original.rsplit('.',1)[1].lower() if '.' in original else '')
    if ext in ('jpg','jpeg','png','gif','webp') and not looks_like_image(head):
        return None
    if ext == 'pdf' and not looks_like_pdf(head):
        return None

    try:
        rel_root = _uploads_rel_root() or 'uploads'
        user_role = getattr(user, 'role', 'user')
        user_id = getattr(user, 'id', 'unknown')
        rel_dir = os.path.join(rel_root, user_role, str(user_id), upload_type).replace('\\', '/')
        full_dir = os.path.join(app.root_path, rel_dir)
        os.makedirs(full_dir, exist_ok=True)

        # UUID-based storage; store original as metadata suffix only
        storage_name = f"{uuid4().hex}__{original}"
        if encrypt:
            storage_name += '.enc'

        full_path = os.path.join(full_dir, storage_name)
        rel_path_for_db = os.path.join(rel_dir, storage_name).replace('\\', '/')

        # Stream to disk; encrypt if configured
        raw = file_obj.read()
        if encrypt:
            encrypted_bytes = encrypt_file_bytes(raw)
            if not encrypted_bytes:
                return None
            with open(full_path, 'wb') as fh:
                fh.write(encrypted_bytes)
        else:
            with open(full_path, 'wb') as fh:
                fh.write(raw)

        return rel_path_for_db
    except Exception as e:
        logging.error(f"File upload error for user {getattr(user,'id','unknown')}: {e}")
        return None


def _delete_local_profile_picture_file(path_value):
    if not path_value or not isinstance(path_value, str):
        return
    if path_value.startswith('http') or path_value.startswith('blob://'):
        return
    try:
        full_path = os.path.join(app.root_path, path_value)
        if os.path.isfile(full_path):
            os.remove(full_path)
    except Exception as err:
        logging.warning(f"Could not delete old profile picture file '{path_value}': {err}")


def _sync_patient_picture_from_user(user, clear=False):
    if not user:
        return None
    try:
        patient = Patient.query.filter_by(user_id=user.id).first()
        if not patient:
            return None
        if clear:
            patient.profile_picture_blob = None
            patient.profile_picture_mime = None
            patient.profile_picture_name = None
            patient.profile_picture = None
            return patient

        patient.profile_picture_blob = user.profile_picture_blob
        patient.profile_picture_mime = user.profile_picture_mime
        patient.profile_picture_name = user.profile_picture_name
        patient.profile_picture = user.profile_picture
        return patient
    except Exception as err:
        logging.warning(f"Could not sync patient profile picture from user {getattr(user, 'id', None)}: {err}")
        return None

# Routes

@app.route('/api/doctors/<int:doctor_id>/profile-with-reviews', methods=['GET'])
def api_doctor_profile_with_reviews(doctor_id: int):
    """Return doctor profile with aggregated ratings and recent testimonials for display.
    Response shape matches frontend expectations in index and appointment pages.
    """
    try:
        doc = db.session.get(Doctor, int(doctor_id))
        if not doc:
            return jsonify({'success': False, 'error': 'doctor_not_found'}), 404
        # Load associated user for name and profile
        usr = db.session.get(User, doc.user_id) if doc.user_id else None
        name = (usr.get_display_name() if usr else doc.get_display_name()) or 'Doctor'
        testimonials = []
        avg = 0.0
        count = 0
        if _table_exists('testimonials'):
            avg_value = db.session.query(func.avg(Testimonial.rating)).filter(Testimonial.doctor_id == doc.id).scalar()
            avg = round(float(avg_value), 1) if avg_value is not None else 0.0
            count = db.session.query(func.count(Testimonial.id)).filter(Testimonial.doctor_id == doc.id).scalar() or 0
            q = Testimonial.query.filter_by(doctor_id=doc.id).order_by(Testimonial.created_at.desc()).limit(20)
            for t in q.all():
                patient_name = 'Patient'
                pic_url = None
                try:
                    if t.patient and t.patient.user:
                        pu = t.patient.user
                        patient_name = pu.get_display_name()
                        if pu.profile_picture:
                            try:
                                pic_url = url_for('profile_picture', user_id=pu.id)
                            except Exception:
                                pic_url = None
                except Exception:
                    pass
                testimonials.append({
                    'patient_name': patient_name,
                    'patient_profile_picture_url': pic_url,
                    'rating': int(t.rating) if t.rating is not None else None,
                    'content': t.content or '',
                    'created_at': t.created_at.isoformat() if t.created_at else None
                })
        payload = {
            'doctor': {
                'id': doc.id,
                'name': f"Dr. {name}",
                'specialization': doc.specialization or '',
                'experience_years': doc.experience_years or 0,
                'qualifications': doc.qualifications or '',
                'average_rating': avg,
                'testimonials_count': int(count),
                'testimonials': testimonials
            },
            'success': True
        }
        return jsonify(payload)
    except Exception as e:
        app.logger.exception('api_doctor_profile_with_reviews failed: %s', e)
        return jsonify({'success': False, 'error': 'server_error'}), 500

@app.route('/')
def index():
    # Get real-time statistics from database
    stats = {
        'total_patients': Patient.query.count(),
        'total_doctors': Doctor.query.count(),
        'total_appointments': Appointment.query.count(),
        'satisfaction_rate': 95  # You can calculate this from feedback/reviews if available
    }
    
    # Get available doctors for the doctors section
    doctors = db.session.query(Doctor, User).join(
        User, Doctor.user_id == User.id
    ).filter(Doctor.availability == True).all()
    
    # Get recent public testimonials
    try:
        testimonials = Testimonial.query.filter_by(is_public=True).order_by(Testimonial.created_at.desc()).limit(6).all()
    except Exception:
        testimonials = []
    
    # If user is authenticated, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif current_user.role == 'customer_care':
            return redirect(url_for('customer_care_dashboard'))
        else:
            return redirect(url_for('patient_dashboard'))
    
    return render_template('index.html', 
                         stats=stats, 
                         doctors=doctors, 
                         testimonials=testimonials)

# Add this function before creating the app
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    """Convert string to datetime and format it"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return value
    if hasattr(value, 'strftime'):
        return value.strftime(format)
    return value

def to_datetime(value):
    """Convert string to datetime object"""
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return value
    return value

# Register the filters
app.jinja_env.filters['datetimeformat'] = datetimeformat
app.jinja_env.filters['to_datetime'] = to_datetime

def _from_json(value):
    """Parse a JSON string into a dict/list."""
    if not value or not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return value

app.jinja_env.filters['from_json'] = _from_json

# Dedicated About page
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        old_username = current_user.username
        # Handle profile picture upload, username, password, theme, wallpaper, etc.
        # Implement logic for each field as needed
        # Determine requested username and apply early so uploads land in new folder
        requested_username = request.form.get('username')
        if requested_username:
            requested_username = secure_filename(requested_username)
        # Apply username change in-memory first so uploaded files use the new folder
        if requested_username and requested_username != current_user.username:
            current_user.username = requested_username

        # Example: handle profile picture
        profile_picture = request.files.get('profile_picture')
        if profile_picture and profile_picture.filename:
            pic_path = handle_file_upload(current_user, profile_picture, upload_type='profile_pics', encrypt=True)
            if pic_path:
                current_user.profile_picture = pic_path
                if current_user.role == 'patient':
                    synced_patient = _sync_patient_picture_from_user(current_user)
                    if synced_patient:
                        db.session.add(synced_patient)
                flash('Profile picture updated successfully', 'success')
            else:
                flash('Invalid profile picture file type or upload failed.', 'error')
        # Note: username already applied above before handling uploads
        # Example: handle password change
        new_password = request.form.get('new_password')
        if new_password:
            current_user.set_password(new_password)
        # Example: handle theme
        theme = request.form.get('theme')
        if theme:
            current_user.theme = theme
        # Persist preferred timezone (IANA string); defaulting handled on client if absent
        tz = request.form.get('timezone')
        if tz:
            try:
                current_user.last_known_timezone = tz
            except Exception:
                pass
        # Role-specific toggles
        if current_user.role == 'admin':
            allow_user_creation = True if request.form.get('allow_user_creation') else False
            try:
                current_user.allow_user_creation = allow_user_creation
            except Exception:
                pass
        elif current_user.role == 'doctor':
            show_availability = True if request.form.get('show_availability') else False
            try:
                current_user.show_availability = show_availability
            except Exception:
                pass
        else:
            share_data = True if request.form.get('share_data') else False
            try:
                current_user.share_data = share_data
            except Exception:
                pass
        # Example: handle wallpaper (saved under uploads but not encrypted)
        wallpaper = request.files.get('wallpaper')
        if wallpaper and wallpaper.filename:
            filename = secure_filename(wallpaper.filename)
            if allowed_file(filename):
                username_for = safe_username(current_user)
                rel_root = _uploads_rel_root() or 'uploads'
                rel_dir = os.path.join(rel_root, username_for, 'wallpapers').replace('\\', '/')
                full_dir = os.path.join(app.root_path, rel_dir)
                os.makedirs(full_dir, exist_ok=True)
                stored_name = f"{uuid4().hex}__{filename}"
                dest_path = os.path.join(full_dir, stored_name)
                wallpaper.save(dest_path)
                current_user.wallpaper = os.path.join(rel_dir, stored_name).replace('\\', '/')
            else:
                flash('Invalid wallpaper file type.', 'error')
        db.session.commit()

        # If username changed, attempt to migrate existing uploads folder and update paths
        try:
            new_username = current_user.username
            if old_username and new_username and old_username != new_username:
                old_dir = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), old_username)
                new_dir = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), new_username)
                if os.path.exists(old_dir) and not os.path.exists(new_dir):
                    os.makedirs(os.path.dirname(new_dir), exist_ok=True)
                    os.rename(old_dir, new_dir)
                # Update stored paths on the user record that referenced old_username
                updated = False
                if current_user.profile_picture and old_username in current_user.profile_picture:
                    current_user.profile_picture = current_user.profile_picture.replace(old_username, new_username)
                    updated = True
                if getattr(current_user, 'wallpaper', None) and old_username in current_user.wallpaper:
                    current_user.wallpaper = current_user.wallpaper.replace(old_username, new_username)
                    updated = True
                if updated:
                    db.session.add(current_user)
                    db.session.commit()
        except Exception:
            db.session.rollback()
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings'))
    return render_template('settings/settings.html')
@app.route('/about')
def about():
    # Render a dedicated About page
    return render_template('about.html')


@app.route('/services')
def services():
    """Services page listing telemedicine and in-facility services"""
    sc = _get_site_content_dict()
    svc = sc.get('services', {})

    # Use CMS values if available, fall back to hardcoded defaults
    tele_raw = svc.get('telemedicine_items')
    if isinstance(tele_raw, list) and tele_raw:
        telemedicine_services = tele_raw
    else:
        telemedicine_services = [
            'Video consultations',
            'Voice consultations',
            'Secure messaging with clinicians',
            'E-prescriptions and medication management',
            'Remote monitoring and follow-up',
            'Online referrals and test ordering'
        ]

    fac_raw = svc.get('facility_items')
    if isinstance(fac_raw, list) and fac_raw:
        facility_services = fac_raw
    else:
        facility_services = [
            'In-person specialist consultations',
            'Laboratory tests and imaging',
            'Minor procedures and wound care',
            'Pharmacy and medication pickup',
            'Vaccinations and preventive services',
            'Emergency and urgent care'
        ]

    return render_template('services.html',
                           telemedicine_services=telemedicine_services,
                           facility_services=facility_services)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Accept either username or email in the same field (legacy name 'email').
        login_input = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        remember = True if request.form.get('remember') else False

        if not login_input or not password:
            flash('Please enter both username/email and password', 'error')
            return render_template('auth/login.html')

        user = None
        # Try a case-insensitive username match first
        try:
            user = User.query.filter(func.lower(User.username) == login_input.lower()).first()
        except Exception:
            # Fallback to exact username if DB backend doesn't support func.lower
            user = User.query.filter_by(username=login_input).first()

        # If not found by username, try email lookup via deterministic hash
        if not user:
            user = User.query.filter_by(email_hash=_hash_value(login_input.lower())).first()

        if user and user.check_password(password):
            if user.is_active:
                if not bool(getattr(user, 'email_verified', False)):
                    session['pending_email_verify_user_id'] = user.id
                    session['pending_email_verify_remember'] = bool(remember)
                    session['pending_email_verify_next'] = request.args.get('next')
                    flash('Please verify your email before logging in.', 'warning')
                    return redirect(url_for('verify_login_email'))

                login_user(user, remember=remember)
                flash('Login successful!', 'success')

                # Log login action
                audit_log = AuditLog(
                    user_id=user.id,
                    action='login',
                    description=f'User {user.get_display_name()} logged in',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()

                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                if not getattr(user, 'email_verified', False):
                    flash('Account is inactive and email is not verified. Contact administrator.', 'warning')
                else:
                    flash('Account is deactivated. Please contact administrator.', 'error')
        else:
            flash('Invalid username/email or password. Please try again.', 'error')

    return render_template('auth/login.html')


@app.route('/verify-login-email', methods=['GET'])
def verify_login_email():
    pending_user_id = session.get('pending_email_verify_user_id')
    if not pending_user_id:
        flash('Verification session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    user = db.session.get(User, int(pending_user_id))
    if not user:
        session.pop('pending_email_verify_user_id', None)
        session.pop('pending_email_verify_remember', None)
        session.pop('pending_email_verify_next', None)
        flash('Verification session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    if bool(getattr(user, 'email_verified', False)):
        remember = bool(session.get('pending_email_verify_remember'))
        next_page = session.get('pending_email_verify_next')
        login_user(user, remember=remember)
        session.pop('pending_email_verify_user_id', None)
        session.pop('pending_email_verify_remember', None)
        session.pop('pending_email_verify_next', None)
        return redirect(next_page) if next_page else redirect(url_for('index'))

    return render_template('auth/verify_login_email.html', pending_email=getattr(user, 'email', ''), pending_user=user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Process form data
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '').strip()
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            phone = request.form.get('phone', '').strip()
            date_of_birth = request.form.get('date_of_birth', '').strip()
            otp_challenge_id = request.form.get('email_otp_challenge_id', '').strip()
            otp_verified_flag = (request.form.get('email_otp_verified', 'false') or '').strip().lower() == 'true'

            # Validate required fields
            if not all([username, email, password, first_name, last_name]):
                flash('Please fill in all required fields', 'error')
                return render_template('auth/signup.html')

            # Validate password strength
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return render_template('auth/signup.html')

            # Check if user exists
            if User.query.filter_by(email_hash=_hash_value(email)).first():
                flash('Email already registered', 'error')
                return render_template('auth/signup.html')

            if User.query.filter_by(username=username).first():
                flash('Username already taken', 'error')
                return render_template('auth/signup.html')

            if not otp_verified_flag:
                flash('Please verify your email with the OTP code before creating an account.', 'error')
                return render_template('auth/signup.html')

            challenge, challenge_error = _consume_verified_otp_challenge(email, 'signup', otp_challenge_id)
            if challenge_error:
                db.session.rollback()
                flash('Email OTP verification is required and must be completed again.', 'error')
                return render_template('auth/signup.html')

            # Create new user
            user = User(
                username=username,
                email=email,
                role='patient',
                is_active=True
            )
            user.email_verified = True
            user.set_password(password)
            user.first_name = first_name
            user.last_name = last_name
            if phone:
                user.phone = phone

            db.session.add(user)
            db.session.commit()  # Commit to get user ID

            # Create patient profile
            patient = Patient(user_id=user.id)

            # Optional patient fields (only set if provided)
            gender = request.form.get('gender', '').strip() or None
            blood_type = request.form.get('blood_type', '').strip() or None
            address = request.form.get('address', '').strip() or None
            city = request.form.get('city', '').strip() or None
            country = request.form.get('country', '').strip() or None
            postal_code = request.form.get('postal_code', '').strip() or None
            occupation = request.form.get('occupation', '').strip() or None
            nationality = request.form.get('nationality', '').strip() or None
            marital_status = request.form.get('marital_status', '').strip() or None
            preferred_language = request.form.get('preferred_language', '').strip() or None
            height_cm = request.form.get('height_cm', '').strip() or None
            weight_kg = request.form.get('weight_kg', '').strip() or None
            id_number = request.form.get('id_number', '').strip() or None
            emergency_contact = request.form.get('emergency_contact', '').strip() or None
            insurance_provider = request.form.get('insurance_provider', '').strip() or None
            insurance_number = request.form.get('insurance_number', '').strip() or None
            current_medications = request.form.get('current_medications', '').strip() or None
            medical_history = request.form.get('medical_history', '').strip() or None

            # Server-side validation helpers
            def _valid_height(h):
                try:
                    v = float(h)
                    return 30.0 <= v <= 272.0
                except Exception:
                    return False

            def _valid_weight(w):
                try:
                    v = float(w)
                    return 1.0 <= v <= 500.0
                except Exception:
                    return False

            def _valid_dob(d):
                try:
                    dob_dt = datetime.strptime(d, '%Y-%m-%d').date()
                    today = now_eat().date()
                    if dob_dt > today:
                        return False
                    age = today.year - dob_dt.year - ((today.month, today.day) < (dob_dt.month, dob_dt.day))
                    return 0 <= age <= 130
                except Exception:
                    return False

            try:
                if date_of_birth:
                    if _valid_dob(date_of_birth):
                        user.date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
                    else:
                        if app.config.get('STRICT_PROFILE_VALIDATION', False):
                            flash('Date of birth is invalid. Please correct it.', 'error')
                            return render_template('auth/signup.html')
                        else:
                            flash('Date of birth looks invalid and was not saved.', 'warning')
                            user.date_of_birth = None
            except Exception:
                user.date_of_birth = None

            # assign optional patient fields
            if gender:
                patient.gender = gender
            if blood_type:
                patient.blood_type = blood_type
            if address:
                patient.address = address
            if city:
                patient.city = city
            if country:
                patient.country = country
            if postal_code:
                patient.postal_code = postal_code
            if occupation:
                patient.occupation = occupation
            if nationality:
                patient.nationality = nationality
            if marital_status:
                patient.marital_status = marital_status
            if preferred_language:
                patient.preferred_language = preferred_language
            if id_number:
                patient.id_number = id_number
            if emergency_contact:
                patient.emergency_contact = emergency_contact
            if insurance_provider:
                patient.insurance_provider = insurance_provider
            if insurance_number:
                patient.insurance_number = insurance_number
            if current_medications:
                patient.current_medications = current_medications
            if medical_history:
                patient.medical_history = medical_history

            # numeric conversions with validation
            if height_cm:
                if _valid_height(height_cm):
                    patient.height_cm = float(height_cm)
                else:
                    if app.config.get('STRICT_PROFILE_VALIDATION', False):
                        flash('Height value is invalid. Please correct it.', 'error')
                        return render_template('auth/signup.html')
                    else:
                        flash('Height value looks out of range and was not saved.', 'warning')
            if weight_kg:
                if _valid_weight(weight_kg):
                    patient.weight_kg = float(weight_kg)
                else:
                    if app.config.get('STRICT_PROFILE_VALIDATION', False):
                        flash('Weight value is invalid. Please correct it.', 'error')
                        return render_template('auth/signup.html')
                    else:
                        flash('Weight value looks out of range and was not saved.', 'warning')
            db.session.add(patient)
            db.session.commit()

            # Send role-based welcome email
            try:
                email_result = send_welcome_email(user)
                if email_result['success']:
                    flash('Account created successfully. Your email has been verified via OTP.', 'success')
                else:
                    app.logger.warning(f'Welcome email failed for user {user.id}: {email_result["message"]}')
                    flash('Account created and email verified, but welcome email could not be sent right now.', 'warning')
            except Exception as e:
                app.logger.error(f'Exception sending welcome email: {str(e)}')
                flash('Account created and email verified successfully.', 'success')
            
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'error')
            print(f"Signup error: {str(e)}")  # For debugging
            return render_template('auth/signup.html')

    return render_template('auth/signup.html')

@app.route('/logout')
@login_required
def logout():
    # Log logout action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='logout',
        description=f'User {current_user.username} logged out',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/verify-email/<token>')
def verify_email(token):
    """Verify user email address via token from email link"""
    try:
        # Find user by verification token
        user = User.query.filter_by(email_verification_token=token).first()
        
        if not user:
            flash('Invalid or expired verification link.', 'error')
            return redirect(url_for('login'))
        
        # Mark email as verified and activate account
        should_send_welcome = not bool(getattr(user, 'is_active', False))
        user.email_verified = True
        user.is_active = True
        if is_practitioner_user(user) and not has_practitioner_license_compliance(user):
            user.is_active = False
        user.email_verification_token = None  # Clear the token after use
        db.session.commit()

        if should_send_welcome:
            try:
                send_welcome_email(user)
            except Exception as e:
                app.logger.warning(f'Welcome email failed after verification for user {user.id}: {str(e)}')
        
        # Log the action
        audit_log = AuditLog(
            user_id=user.id,
            action='email_verified',
            description=f'Email verified for {user.email}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        if user.is_active:
            flash('Email verified and account activated successfully! You can now log in.', 'success')
        else:
            flash('Email verified, but account remains inactive pending practitioner license compliance review.', 'warning')
        return redirect(url_for('login'))
    
    except Exception as e:
        app.logger.error(f'Error verifying email: {str(e)}')
        flash('Error verifying email. Please try again or contact support.', 'error')
        return redirect(url_for('index'))


@app.route('/resend-verification-email')
@login_required
def resend_verification_email():
    """Allow user to request a new verification email"""
    try:
        if current_user.email_verified:
            flash('Your email is already verified.', 'info')
            return redirect(url_for('settings'))
        
        # Send new verification email
        result = send_verification_email(current_user)
        
        if result['success']:
            flash('Verification email sent! Check your inbox.', 'success')
        else:
            flash('Failed to send verification email. Please try again later.', 'error')
        
        return redirect(url_for('settings'))
    
    except Exception as e:
        app.logger.error(f'Error resending verification email: {str(e)}')
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('settings'))


@app.route('/patient/dashboard')
@login_required
def patient_dashboard():
    try:
        if current_user.role != 'patient':
            flash('Access denied', 'error')
            return redirect(url_for('index'))
        
        print(f"Loading dashboard for patient: {current_user.id}")  # Debug log
        
        # Find patient by user_id, not patient.id
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            print("Patient profile not found, creating one...")  # Debug log
            # Create patient profile if it doesn't exist
            patient = Patient(user_id=current_user.id)
            db.session.add(patient)
            db.session.commit()
            flash('Patient profile created successfully', 'success')
        
        print(f"Patient profile found: {patient.id}")  # Debug log
        
        # Get upcoming appointments for dashboard with proper data structure
        upcoming_appointments = []
        try:
            # Use timezone-aware datetime to fix deprecation warning
            from datetime import timezone
            now = now_eat()
            
            upcoming_appointments_data = db.session.query(
                Appointment,
                Doctor,
                User
            ).join(
                Doctor, Appointment.doctor_id == Doctor.id
            ).join(
                User, Doctor.user_id == User.id
            ).filter(
                Appointment.patient_id == patient.id,
                Appointment.status.in_(['confirmed', 'scheduled']),
                Appointment.appointment_date > now
            ).order_by(Appointment.appointment_date.asc()).limit(5).all()
            
            # Convert to template-friendly format with proper structure
            for appointment, doctor, user in upcoming_appointments_data:
                upcoming_appointments.append({
                    'id': appointment.id,
                    'appointment_date': appointment.appointment_date,
                    'consultation_type': appointment.consultation_type,
                    'symptoms': appointment.symptoms,
                    'status': appointment.status,
                    'doctor': {
                        'id': doctor.id,
                        'specialization': doctor.specialization,
                        'user': {
                            'id': user.id,
                            'first_name': user.first_name,
                            'last_name': user.last_name
                        }
                    }
                })
                
            print(f"Found {len(upcoming_appointments)} upcoming appointments")  # Debug log
            
        except Exception as e:
            print(f"Error loading appointments: {e}")  # Debug log
            import traceback
            traceback.print_exc()
            # Continue without appointments if there's an error
        
        # Get patient vitals if available
        vitals = None
        try:
            vitals = PatientVital.query.filter_by(patient_id=patient.id).order_by(PatientVital.recorded_at.desc()).first()
        except Exception as e:
            print(f"Error loading vitals: {e}")  # Debug log
            # Table might not exist yet, that's OK
        
        # Calculate BMI if height and weight are available
        bmi = None
        bmi_category = None
        try:
            if patient.height_cm and patient.weight_kg:
                height_m = patient.height_cm / 100
                bmi = round(patient.weight_kg / (height_m * height_m), 1)
                if bmi < 18.5:
                    bmi_category = 'Underweight'
                elif bmi < 25:
                    bmi_category = 'Normal'
                elif bmi < 30:
                    bmi_category = 'Overweight'
                else:
                    bmi_category = 'Obese'
        except Exception as e:
            print(f"Error calculating BMI: {e}")  # Debug log
        
        # Get medications and allergies
        medications = []
        allergies = []
        try:
            if patient.current_medications:
                medications = [med.strip() for med in patient.current_medications.split(',') if med.strip()]
            if patient.allergies:
                allergies = [allergy.strip() for allergy in patient.allergies.split(',') if allergy.strip()]
        except Exception as e:
            print(f"Error processing medications/allergies: {e}")  # Debug log
        
        # Recent activity (simplified - you can enhance this)
        recent_activity = []
        try:
            # Get recent communications
            recent_comms = db.session.query(
                Communication,
                Appointment
            ).join(
                Appointment, Communication.appointment_id == Appointment.id
            ).filter(
                Appointment.patient_id == patient.id
            ).order_by(Communication.timestamp.desc()).limit(5).all()
            
            for comm, apt in recent_comms:
                doctor_name = "Doctor"
                try:
                    if apt and apt.doctor and apt.doctor.user:
                        doctor_name = f"Dr. {apt.doctor.user.first_name}"
                except Exception:
                    pass
                    
                recent_activity.append({
                    'type': 'message',
                    'time': comm.timestamp,
                    'text': f"Message from {doctor_name}"
                })
        except Exception as e:
            print(f"Error loading recent activity: {e}")  # Debug log
        
        print("Rendering dashboard template...")  # Debug log
        
        return render_template('patient/patient_dashboard.html', 
                             user=current_user, 
                             patient=patient,
                             appointments=upcoming_appointments,  # This is now a list of dictionaries
                             vitals=vitals,
                             bmi=bmi,
                             bmi_category=bmi_category,
                             medications=medications,
                             allergies=allergies,
                             recent_activity=recent_activity)
                             
    except Exception as e:
        print(f"Critical error in patient dashboard: {e}")  # Debug log
        import traceback
        traceback.print_exc()  # Print full traceback
        flash('Error loading dashboard. Please try again.', 'error')
        return redirect(url_for('index'))

# Patient Appointments Page
@app.route('/patient/appointment')
@login_required
def patient_appointment():
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    patient = current_user.patient_profile
    if not patient:
        flash('Patient profile not found', 'error')
        return redirect(url_for('patient_dashboard'))
    
    # Get all doctors for the booking form - properly structured
    doctors_data = db.session.query(Doctor, User).join(
        User, Doctor.user_id == User.id
    ).filter(Doctor.availability == True).all()
    
    # Convert to a more template-friendly format
    doctors = []
    for doctor, user in doctors_data:
        doctors.append({
            'id': doctor.id,
            'user': {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name
            },
            'specialization': doctor.specialization,
            'consultation_fee': doctor.consultation_fee
        })
    
    # Get categorized appointments - properly flatten and categorize
    try:
        now = now_eat()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)
        
        appointments_query = db.session.query(
            Appointment,
            Doctor,
            User,
            Payment
        ).join(
            Doctor, Appointment.doctor_id == Doctor.id
        ).join(
            User, Doctor.user_id == User.id
        ).outerjoin(
            Payment, Appointment.id == Payment.appointment_id
        ).filter(
            Appointment.patient_id == patient.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Categorize appointments
        upcoming = []
        pending_confirmation = []
        completed = []
        rescheduled = []
        
        for appointment, doctor, user, payment in appointments_query:
            # Determine payment status
            payment_status = 'pending'
            if payment:
                payment_status = payment.status
            elif appointment.status == 'completed':
                payment_status = 'completed'
            
            appointment_data = {
                'id': appointment.id,
                'doctor': {
                    'id': doctor.id,
                    'user': {
                        'id': user.id,
                        'first_name': user.first_name,
                        'last_name': user.last_name
                    },
                    'specialization': doctor.specialization,
                    'consultation_fee': float(doctor.consultation_fee) if doctor.consultation_fee else 0.0
                },
                'appointment_date': appointment.appointment_date,
                'appointment_date_formatted': appointment.appointment_date.strftime('%d %b %Y') if appointment.appointment_date else None,
                'appointment_time': appointment.appointment_date.strftime('%H:%M') if appointment.appointment_date else None,
                'consultation_type': appointment.consultation_type,
                'symptoms': appointment.symptoms,
                'notes': appointment.notes,
                'status': appointment.status,
                'payment_status': payment_status,
                'rating': appointment.rating if hasattr(appointment, 'rating') else None,
                'created_at': appointment.created_at
            }
            
            # Categorize based on status and date
            if appointment.status == 'completed':
                completed.append(appointment_data)
            elif appointment.status == 'rescheduled':
                rescheduled.append(appointment_data)
            elif appointment.status == 'pending':
                pending_confirmation.append(appointment_data)
            elif appointment.status in ['confirmed', 'scheduled']:
                upcoming.append(appointment_data)
            else:
                # Default to pending confirmation for unknown statuses
                pending_confirmation.append(appointment_data)
        
        appointments_data = {
            'upcoming': upcoming,
            'pending_confirmation': pending_confirmation,
            'completed': completed,
            'rescheduled': rescheduled
        }
    except Exception as e:
        print(f"Error getting appointments: {e}")
        import traceback
        traceback.print_exc()
        appointments_data = {
            'upcoming': [],
            'pending_confirmation': [],
            'completed': [],
            'rescheduled': []
        }


    return render_template('patient/appointment.html', 
                         user=current_user, 
                         patient=patient,
                         doctors=doctors,
                         upcoming=appointments_data.get('upcoming', []),
                         pending_confirmation=appointments_data.get('pending_confirmation', []),
                         completed=appointments_data.get('completed', []),
                         rescheduled=appointments_data.get('rescheduled', []))

# ── Patient My Prescriptions ─────────────────────────────────────────
@app.route('/patient/my-prescriptions')
@login_required
def patient_my_prescriptions():
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    patient = current_user.patient_profile
    if not patient:
        flash('Patient profile not found', 'error')
        return redirect(url_for('patient_dashboard'))

    prescriptions = (
        Prescription.query
        .filter_by(patient_id=patient.id)
        .order_by(Prescription.created_at.desc())
        .all()
    )

    return render_template(
        'patient/my_prescriptions.html',
        prescriptions=prescriptions,
        patient=patient
    )

@app.route('/patient/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_patient_profile():
    # Only patients may edit their patient profile here
    if current_user.role != 'patient':
        flash('Only patients can edit patient profiles.', 'error')
        return redirect(url_for('index'))

    # Ensure a Patient row exists for this user
    patient = current_user.patient_profile
    if not patient:
        patient = Patient(user_id=current_user.id)
        db.session.add(patient)
        db.session.commit()

    if request.method == 'POST':
        # Basic user fields
        first_name = request.form.get('first_name', '').strip() or None
        last_name = request.form.get('last_name', '').strip() or None
        phone = request.form.get('phone', '').strip() or None
        dob = request.form.get('date_of_birth', '').strip() or None

        if first_name is not None:
            current_user.first_name = first_name
        if last_name is not None:
            current_user.last_name = last_name
        if phone is not None:
            current_user.phone = phone

        try:
            if dob:
                current_user.date_of_birth = datetime.strptime(dob, '%Y-%m-%d').date()
            else:
                current_user.date_of_birth = None
        except Exception:
            pass

        # patient optional fields
        patient.gender = request.form.get('gender', '').strip() or None
        patient.blood_type = request.form.get('blood_type', '').strip() or None
        patient.address = request.form.get('address', '').strip() or None
        patient.city = request.form.get('city', '').strip() or None
        patient.country = request.form.get('country', '').strip() or None
        patient.postal_code = request.form.get('postal_code', '').strip() or None
        patient.occupation = request.form.get('occupation', '').strip() or None
        patient.nationality = request.form.get('nationality', '').strip() or None
        patient.marital_status = request.form.get('marital_status', '').strip() or None
        patient.preferred_language = request.form.get('preferred_language', '').strip() or None
        patient.id_number = request.form.get('id_number', '').strip() or None
        patient.emergency_contact = request.form.get('emergency_contact', '').strip() or None
        patient.insurance_provider = request.form.get('insurance_provider', '').strip() or None
        patient.insurance_number = request.form.get('insurance_number', '').strip() or None
        patient.current_medications = request.form.get('current_medications', '').strip() or None
        patient.medical_history = request.form.get('medical_history', '').strip() or None

        try:
            h = request.form.get('height_cm', '').strip()
            w = request.form.get('weight_kg', '').strip()
            if h:
                patient.height_cm = float(h)
            else:
                patient.height_cm = None
            if w:
                patient.weight_kg = float(w)
            else:
                patient.weight_kg = None
        except Exception:
            pass

        # validate server-side DOB/height/weight again before commit
        def _valid_height(h):
            try:
                v = float(h)
                return 30.0 <= v <= 272.0
            except Exception:
                return False

        def _valid_weight(w):
            try:
                v = float(w)
                return 1.0 <= v <= 500.0
            except Exception:
                return False

        def _valid_dob(d):
            try:
                dob_dt = datetime.strptime(d, '%Y-%m-%d').date()
                today = now_eat().date()
                if dob_dt > today:
                    return False
                age = today.year - dob_dt.year - ((today.month, today.day) < (dob_dt.month, dob_dt.day))
                return 0 <= age <= 130
            except Exception:
                return False

        # Ensure stored numeric values are within reasonable ranges, otherwise clear and warn or block
        try:
            if current_user.date_of_birth:
                # already parsed earlier
                pass
        except Exception:
            pass

        if patient.height_cm is not None:
            try:
                if not _valid_height(patient.height_cm):
                    if app.config.get('STRICT_PROFILE_VALIDATION', False):
                        flash('Height value is invalid. Please correct it.', 'error')
                        return redirect(url_for('edit_patient_profile'))
                    else:
                        patient.height_cm = None
                        flash('Height out of range; cleared.', 'warning')
            except Exception:
                patient.height_cm = None

        if patient.weight_kg is not None:
            try:
                if not _valid_weight(patient.weight_kg):
                    if app.config.get('STRICT_PROFILE_VALIDATION', False):
                        flash('Weight value is invalid. Please correct it.', 'error')
                        return redirect(url_for('edit_patient_profile'))
                    else:
                        patient.weight_kg = None
                        flash('Weight out of range; cleared.', 'warning')
            except Exception:
                patient.weight_kg = None

        try:
            db.session.commit()
            flash('Profile updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile: ' + str(e), 'error')

        return redirect(url_for('edit_patient_profile'))

    # GET -> render form with existing values
    return render_template('patient/edit_profile.html', user=current_user, patient=patient)

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Please enter your email address.', 'error')
            return redirect(url_for('forgot_password'))

        user = User.query.filter_by(email_hash=_hash_value(email)).first()
        
        if not user:
            flash('No account found with that email address.', 'error')
            return redirect(url_for('forgot_password'))

        # Generate reset token using itsdangerous serializer
        token = s.dumps(email, salt='password-reset-salt')
        
        try:
            # Send password reset email using Resend
            result = send_password_reset_email(user, token)
            
            if result.get('success'):
                # Log the action
                audit_log = AuditLog(
                    user_id=user.id,
                    action='password_reset_request',
                    description=f'Password reset requested for {email}',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()
                flash('Password reset link sent. Check your email inbox.', 'success')
            else:
                app.logger.error(f'Failed to send reset email: {result.get("message")}')
                flash(f'Failed to send reset email: {result.get("message")}', 'error')
            
        except Exception as e:
            app.logger.error(f'Exception in forgot_password: {str(e)}')
            flash('Failed to send reset email due to a server error.', 'error')
        
        return redirect(url_for('forgot_password'))
    
    return render_template('auth/forgot_password.html')

# Reset Password Route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verify token (valid for 1 hour)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid password reset link. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email_hash=_hash_value(email)).first()
    if not user:
        flash('Invalid password reset link.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        # Validate password strength
        if not validate_password_strength(new_password):
            flash('Password does not meet security requirements.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        # Log the action
        audit_log = AuditLog(
            user_id=user.id,
            action='password_reset_success',
            description='Password reset successfully',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Your password has been reset successfully. Please log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/reset_password.html', token=token)

# Password Strength Validation Function
def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False
    
    # Check for uppercase, lowercase, numbers, and special characters
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    return has_upper and has_lower and has_digit and has_special

# Generate Random Password (optional feature)
@app.route('/generate_password')
def generate_password():
    """Generate a secure random password"""
    length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return jsonify({'password': password})

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Real-time statistics from database
    stats = {
        'total_patients': Patient.query.count(),
        'total_doctors': Doctor.query.count(),
        'total_appointments': Appointment.query.count(),
        'pending_appointments': Appointment.query.filter_by(status='scheduled').count(),
        'completed_appointments': Appointment.query.filter_by(status='completed').count(),
        'cancelled_appointments': Appointment.query.filter_by(status='cancelled').count(),
        'today_appointments': Appointment.query.filter(
            db.func.date(Appointment.appointment_date) == datetime.today().date()
        ).count()
    }
    
    # Recent activity from audit logs
    recent_activities = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    # Today's appointments: join Appointment -> Patient -> PatientUser and Appointment -> Doctor -> DoctorUser
    PatientUser = aliased(User)
    DoctorUser = aliased(User)
    today_appointments = db.session.query(
        Appointment, Patient, Doctor, PatientUser, DoctorUser
    ).join(
        Patient, Appointment.patient_id == Patient.id
    ).join(
        PatientUser, Patient.user_id == PatientUser.id
    ).join(
        Doctor, Appointment.doctor_id == Doctor.id
    ).join(
        DoctorUser, Doctor.user_id == DoctorUser.id
    ).filter(
        db.func.date(Appointment.appointment_date) == datetime.today().date()
    ).order_by(Appointment.appointment_date).all()
    
    # System metrics (these can be real if you have monitoring)
    system_metrics = {
        'server_uptime': 99.8,  # This would come from your monitoring system
        'database_performance': 95,
        'storage_usage': 75,
        'network_latency': 98
    }
    
    return render_template('admin/admin_dashboard.html', 
                         stats=stats,
                         recent_activities=recent_activities,
                         today_appointments=today_appointments,
                         system_metrics=system_metrics)


@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if not current_user_has_role('doctor'):
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    if not has_practitioner_license_compliance(current_user):
        flash('Practitioner license compliance is required before accessing doctor tools. Please update your profile and contact admin.', 'warning')
        return redirect(url_for('settings'))

    try:
        # Load doctor profile
        doctor = current_user.doctor_profile
        if not doctor:
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        
        if not doctor:
            flash('Doctor profile not found', 'error')
            return redirect(url_for('index'))

        # Today's appointments for this doctor (filter by date only, not time)
        try:
            from datetime import datetime, timezone, date
            today = date.today()
            # Filter appointments where the date part matches today
            appointments = []
            all_appointments = Appointment.query.filter_by(doctor_id=doctor.id).order_by(Appointment.appointment_date).all()
            for appt in all_appointments:
                appt_date = appt.appointment_date.date() if appt.appointment_date else None
                if appt_date == today:
                    appointments.append(appt)
        except Exception as e:
            print(f"Error loading appointments: {e}")
            appointments = []

        # Patients seen this week
        from datetime import datetime, timedelta, timezone
        now_utc = now_eat()
        start_week = now_utc - timedelta(days=now_utc.weekday())
        
        try:
            from sqlalchemy import func
            patients_this_week_result = db.session.query(func.count(func.distinct(Appointment.patient_id))).filter(
                Appointment.doctor_id == doctor.id,
                Appointment.appointment_date >= start_week
            ).scalar()
            patients_this_week = int(patients_this_week_result) if patients_this_week_result else 0
        except Exception as e:
            print(f"Error counting patients this week: {e}")
            patients_this_week = 0

        # Pending prescriptions (appointments with status 'scheduled' and not completed)
        try:
            pending_prescriptions = Appointment.query.filter_by(doctor_id=doctor.id, status='scheduled').count()
        except Exception as e:
            print(f"Error counting pending prescriptions: {e}")
            pending_prescriptions = 0

        # Urgent cases (appointments with status 'urgent')
        try:
            urgent_cases = Appointment.query.filter_by(doctor_id=doctor.id, status='urgent').count()
        except Exception as e:
            print(f"Error counting urgent cases: {e}")
            urgent_cases = 0

        # Helper to format last visit as 'time ago' string
        def format_timeago(dt):
            if not dt:
                return "N/A"
            now = now_eat()
            # Ensure dt is timezone-aware (convert if naive)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=EAT_TZ)
            diff = now - dt if now > dt else dt - now
            seconds = diff.total_seconds()
            if seconds < 60:
                return f"{int(seconds)} seconds ago"
            elif seconds < 3600:
                return f"{int(seconds // 60)} minutes ago"
            elif seconds < 86400:
                return f"{int(seconds // 3600)} hours ago"
            elif seconds < 604800:
                return f"{int(seconds // 86400)} days ago"
            else:
                return dt.strftime('%b %d, %Y')

        # Recent patients (last 6 unique patients by last appointment)
        recent_patients = []
        try:
            from sqlalchemy import desc
            appts = Appointment.query.filter_by(doctor_id=doctor.id).order_by(desc(Appointment.appointment_date)).all()
            seen = set()
            for appt in appts:
                pid = appt.patient_id
                if pid not in seen:
                    patient = db.session.get(Patient, pid)
                    if patient and patient.user:
                        recent_patients.append({
                            'user': patient.user,
                            'last_visit': format_timeago(appt.appointment_date)
                        })
                        seen.add(pid)
                if len(recent_patients) >= 6:
                    break
        except Exception as e:
            print(f"Error loading recent patients: {e}")
            recent_patients = []

        # Recent activity (communications with user info for profile pictures)
        recent_activity = []
        try:
            from sqlalchemy import desc
            recent_comms = db.session.query(Communication).filter_by().order_by(desc(Communication.timestamp)).limit(10).all()
            seen_comms = set()
            for comm in recent_comms:
                if comm.sender_id not in seen_comms:
                    sender = db.session.get(User, comm.sender_id)
                    if sender:
                        recent_activity.append({
                            'type': 'message',
                            'text': f"Message from {sender.get_display_name()}",
                            'user': sender,
                            'timestamp': comm.timestamp
                        })
                        seen_comms.add(comm.sender_id)
                if len(recent_activity) >= 10:
                    break
        except Exception as e:
            print(f"Error loading recent activity: {e}")
            recent_activity = []

        return render_template(
            'doctor/doctor_dashboard.html',
            doctor=doctor,
            appointments=appointments,
            patients_this_week=patients_this_week,
            pending_prescriptions=pending_prescriptions,
            urgent_cases=urgent_cases,
            recent_patients=recent_patients,
            recent_activity=recent_activity
        )
    
    except Exception as e:
        print(f"Critical error in doctor_dashboard: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading dashboard. Please try again.', 'error')
        return redirect(url_for('index'))
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    users = User.query.filter(User.role != 'patient').order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/api/debug/memory')
@login_required
def debug_memory():
    """Debug endpoint to check memory usage"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    
    return jsonify({
        'rss_mb': memory_info.rss / 1024 / 1024,
        'vms_mb': memory_info.vms / 1024 / 1024,
        'percent': process.memory_percent(),
        'active_users': _count_online_users(),
        'active_calls': len(active_calls)
    })

@app.route('/api/debug/db-check')
def debug_db_check():
    """Debug endpoint to check database status"""
    try:
        # Check if tables exist
        tables = {
            'users': User.query.first() is not None,
            'patients': Patient.query.first() is not None,
            'doctors': Doctor.query.first() is not None,
            'appointments': Appointment.query.first() is not None,
            'payments': Payment.query.first() is not None
        }
        
        # Check appointment columns
        appointment_columns = []
        try:
            test_appt = Appointment()
            appointment_columns = [
                'urgency' if hasattr(test_appt, 'urgency') else 'MISSING: urgency',
                'rating' if hasattr(test_appt, 'rating') else 'MISSING: rating'
            ]
        except Exception as e:
            appointment_columns = [f'Error: {str(e)}']
        
        return jsonify({
            'database_connected': True,
            'tables_exist': tables,
            'appointment_columns': appointment_columns,
            'total_appointments': Appointment.query.count()
        })
    except Exception as e:
        return jsonify({'database_connected': False, 'error': str(e)})

@app.route('/admin/patients')
@login_required
def admin_patients():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    # Parse filters from query string
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()
    blood_type = request.args.get('blood_type', '').strip()
    from_date = request.args.get('from_date', '').strip()

    # Build base query for patients with eager user load
    query = Patient.query.options(joinedload(Patient.user))
    try:
        from sqlalchemy import or_
        if search:
            if '@' in search:
                # email search by deterministic hash
                email_hash = _hash_value(search)
                query = query.join(User).filter(User.email_hash == email_hash)
            else:
                query = query.join(User).filter(
                    or_(
                        User.username.ilike(f"%{search}%"),
                        User.first_name.ilike(f"%{search}%"),
                        User.last_name.ilike(f"%{search}%")
                    )
                )

        if status and status.lower() != 'all status' and status.lower() != 'all':
            if status.lower() == 'active':
                query = query.join(User).filter(User.is_active == True)
            elif status.lower() == 'inactive':
                query = query.join(User).filter(User.is_active == False)

        if blood_type and blood_type.lower() not in ('all blood types', 'all'):
            query = query.filter(Patient.blood_type == blood_type)

        if from_date:
            try:
                fd = datetime.fromisoformat(from_date).date()
                # filter users created on or after this date
                query = query.join(User).filter(func.date(User.created_at) >= fd)
            except Exception:
                pass

        patients = query.all()
    except Exception:
        # Fallback to full list on any unexpected error
        patients = Patient.query.options(joinedload(Patient.user)).all()

    # Compute dashboard statistics from real data
    total_patients = len(patients)

    # Active today: distinct patients with an appointment today
    today = date.today()
    active_today_q = db.session.query(func.count(distinct(Appointment.patient_id))).filter(
        func.date(Appointment.appointment_date) == today
    )
    try:
        active_today = int(active_today_q.scalar() or 0)
    except Exception:
        active_today = 0

    # New this month: users created this month with role patient
    first_day = today.replace(day=1)
    try:
        new_this_month = User.query.filter(
            User.role == 'patient',
            User.created_at >= datetime.combine(first_day, datetime.min.time())
        ).count()
    except Exception:
        new_this_month = 0

    # Pending records: medical records created in the last 7 days (as a reasonable definition)
    seven_days_ago = now_eat() - timedelta(days=7)
    try:
        pending_records = MedicalRecord.query.filter(MedicalRecord.created_at >= seven_days_ago).count()
    except Exception:
        pending_records = 0

    # Build per-patient metadata: visits count and last visit
    patient_items = []
    for patient in patients:
        try:
            visits = Appointment.query.filter_by(patient_id=patient.id).count()
            last_appt = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.appointment_date.desc()).first()
            last_visit = last_appt.appointment_date if last_appt else None
            status = 'Active' if getattr(patient.user, 'is_active', True) else 'Inactive'
        except Exception:
            visits = 0
            last_visit = None
            status = 'Active'

        patient_items.append({
            'patient': patient,
            'visits': visits,
            'last_visit': last_visit,
            'status': status
        })

    return render_template('admin/patients.html',
                         patients=patients,
                         patient_items=patient_items,
                         stats={
                             'total_patients': total_patients,
                             'active_today': active_today,
                             'new_this_month': new_this_month,
                             'pending_records': pending_records
                         },
                         filters={
                             'search': search,
                             'status': status,
                             'blood_type': blood_type,
                             'from_date': from_date
                         },
                         now=now_eat())


@app.route('/admin/patients_data', methods=['GET'])
@login_required
def admin_patients_data():
    """Return patients as JSON for AJAX filtering with paging."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    # params
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()
    blood_type = request.args.get('blood_type', '').strip()
    from_date = request.args.get('from_date', '').strip()
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except Exception:
        page = 1
    try:
        per_page = int(request.args.get('per_page', 12))
        if per_page < 1:
            per_page = 12
    except Exception:
        per_page = 12

    query = Patient.query.options(joinedload(Patient.user))
    try:
        from sqlalchemy import or_
        if search:
            # match username, first name, last name, email (partial) or phone
            query = query.join(User).filter(
                or_(
                    User.username.ilike(f"%{search}%"),
                    User.first_name.ilike(f"%{search}%"),
                    User.last_name.ilike(f"%{search}%"),
                    User.email.ilike(f"%{search}%"),
                    User.phone.ilike(f"%{search}%")
                )
            )

        if status and status.lower() not in ('', 'all', 'all status'):
            if status.lower() == 'active':
                query = query.join(User).filter(User.is_active == True)
            elif status.lower() == 'inactive':
                query = query.join(User).filter(User.is_active == False)

        if blood_type and blood_type.lower() not in ('', 'all', 'all blood types'):
            query = query.filter(Patient.blood_type == blood_type)

        if from_date:
            try:
                fd = datetime.fromisoformat(from_date).date()
                query = query.join(User).filter(func.date(User.created_at) >= fd)
            except Exception:
                pass

        total = query.count()
        pages = (total + per_page - 1) // per_page
        patients = query.order_by(Patient.id.desc()).offset((page - 1) * per_page).limit(per_page).all()

        items = []
        for patient in patients:
            try:
                visits = Appointment.query.filter_by(patient_id=patient.id).count()
                last_appt = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.appointment_date.desc()).first()
                last_visit = last_appt.appointment_date.isoformat() if last_appt else None
                status_text = 'Active' if getattr(patient.user, 'is_active', True) else 'Inactive'
            except Exception:
                visits = 0
                last_visit = None
                status_text = 'Active'

            user = getattr(patient, 'user', None)
            projected_user = build_user_profile_projection(user, viewer=current_user, include_sensitive=True) if user else {}
            items.append({
                'id': patient.id,
                'visits': visits,
                'last_visit': last_visit,
                'status': status_text,
                'blood_type': patient.blood_type,
                'emergency_contact': patient.emergency_contact,
                'allergies': patient.allergies,
                'insurance_provider': patient.insurance_provider,
                'user': {
                    'id': projected_user.get('id') if user else None,
                    'username': projected_user.get('username') if user else None,
                    'first_name': projected_user.get('first_name') if user else None,
                    'last_name': projected_user.get('last_name') if user else None,
                    'email': projected_user.get('email') if user else None,
                    'phone': projected_user.get('phone') if user else None,
                    'profile_picture': getattr(user, 'profile_picture', None) if user else None,
                    'date_of_birth': user.date_of_birth.isoformat() if user and getattr(user, 'date_of_birth', None) else None,
                }
            })

        return jsonify({'items': items, 'total': total, 'page': page, 'per_page': per_page, 'pages': pages})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user_has_role('admin'):
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))

    data = request.form
    # support FormData from fetch/XHR as well as standard form posts
    if not data:
        data = request.get_json() or {}
    role = data.get('role')
    username = data.get('username') or data.get('usernames')
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone = data.get('phone')
    department = (data.get('department') or '').strip() or None
    job_category = (data.get('job_category') or '').strip() or None
    bank_account = (data.get('bank_account') or '').strip() or None
    bank_name = (data.get('bank_name') or '').strip() or None
    bank_account_type = (data.get('bank_account_type') or '').strip() or None
    preferred_payment_method = (data.get('preferred_payment_method') or '').strip() or None
    email_verified = parse_bool_flag(data.get('email_verified'), default=False)
    public_profile_visible = parse_bool_flag(data.get('public_profile_visible'), default=False)
    public_show_consultation_fee = parse_bool_flag(data.get('public_show_consultation_fee'), default=False)
    show_availability = parse_bool_flag(data.get('show_availability'), default=True)
    share_data = parse_bool_flag(data.get('share_data'), default=False)
    staff_group = (data.get('staff_group') or '').strip() or None
    practitioner_type = (data.get('practitioner_type') or '').strip() or None
    professional_title = (data.get('professional_title') or '').strip() or None
    specialization = (data.get('specialization') or '').strip() or None
    license_number = (data.get('license_number') or '').strip() or None
    license_regulatory_body = (data.get('license_regulatory_body') or '').strip() or None
    license_issue_date = parse_iso_date(data.get('license_issue_date'))
    license_expiry_date = parse_iso_date(data.get('license_expiry_date'))
    license_renewal_status = (data.get('license_renewal_status') or '').strip() or None
    qualifications = (data.get('qualifications') or '').strip() or None
    awards_merits = (data.get('awards_merits') or '').strip() or None
    consultation_fee = parse_optional_float(data.get('consultation_fee'))
    send_invitation = str(data.get('send_invitation', 'true')).strip().lower() not in ('0', 'false', 'no', 'off')
    otp_challenge_id = (data.get('email_otp_challenge_id') or '').strip()

    # validate required fields
    if not all([role, email, password, first_name, last_name, username]):
        msg = 'All fields are required.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    if role == 'patient':
        msg = 'Patient accounts are managed from the Patients module.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_patients'))

    if role == 'doctor' and not license_number:
        msg = 'License number is required for practitioner staff.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    if role != 'doctor' and (staff_group == 'practitioner' or practitioner_type):
        msg = 'Practitioner classification requires doctor role and valid license.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    # check username uniqueness
    if User.query.filter_by(username=username).first():
        msg = 'Username already taken.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    # check email uniqueness
    if User.query.filter_by(email_hash=_hash_value(email)).first():
        msg = 'Email already registered.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    challenge, challenge_error = _consume_verified_otp_challenge(email, 'admin_create_user', otp_challenge_id, require_admin=True)
    if challenge_error:
        msg = 'Email OTP verification is required before creating this user.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    try:
        # create user and set encrypted fields via properties
        user = User(
            username=username,
            role=role,
            is_active=True
        )
        user.email = email
        user.first_name = first_name
        user.last_name = last_name
        user.email_verified = True
        if phone:
            user.phone = phone
        user.department = department
        user.job_category = job_category
        user.bank_account = bank_account
        user.bank_name = bank_name
        user.bank_account_type = bank_account_type
        user.preferred_payment_method = preferred_payment_method
        user.public_profile_visible = public_profile_visible
        user.public_show_consultation_fee = public_show_consultation_fee
        user.show_availability = show_availability
        user.share_data = share_data
        user.professional_title = professional_title

        if role == 'doctor':
            user.account_role = 'staff'
            user.staff_group = 'practitioner'
            user.practitioner_type = practitioner_type or 'general_practitioner'
        elif role == 'admin':
            user.account_role = 'admin'
            user.staff_group = staff_group or 'administration'
            user.practitioner_type = practitioner_type if user.staff_group == 'practitioner' else None

        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        invite_result = None

        # create role-specific profile
        if role == 'doctor':
            doctor = Doctor(user_id=user.id)
            if specialization:
                doctor.specialization = specialization
            if license_number:
                doctor.license_number = license_number
            doctor.license_regulatory_body = license_regulatory_body
            doctor.license_issue_date = license_issue_date
            doctor.license_expiry_date = license_expiry_date
            doctor.license_renewal_status = license_renewal_status
            doctor.qualifications = qualifications
            doctor.awards_merits = awards_merits
            if consultation_fee is not None:
                doctor.consultation_fee = consultation_fee
            db.session.add(doctor)
        elif role == 'patient':
            patient = Patient(user_id=user.id)
            db.session.add(patient)

        profile_picture_file = request.files.get('profile_picture') if request.files else None
        if profile_picture_file and profile_picture_file.filename:
            uploaded_path = handle_file_upload(user, profile_picture_file, upload_type='profile_pics', encrypt=True)
            if uploaded_path:
                user.profile_picture = uploaded_path
                db.session.add(user)
                if user.role == 'patient':
                    synced_patient = _sync_patient_picture_from_user(user)
                    if synced_patient:
                        db.session.add(synced_patient)

        db.session.commit()

        if send_invitation:
            invite_result = send_welcome_email(user)

    except Exception as e:
        db.session.rollback()
        msg = f'Error creating user: {str(e)}'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': msg}), 500
        flash(msg, 'error')
        return redirect(url_for('admin_users'))

    # Success — return JSON for AJAX or redirect for normal form post
    success_msg = 'Staff account created successfully. Email was OTP-verified before creation.'
    warning_msg = 'Staff account created and OTP-verified, but welcome email failed to send.'

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        if invite_result is not None and not invite_result.get('success'):
            return jsonify({'success': True, 'user_id': user.id, 'message': warning_msg, 'invite_sent': False})
        return jsonify({'success': True, 'user_id': user.id, 'message': success_msg, 'invite_sent': True})

    if invite_result is not None and not invite_result.get('success'):
        flash(warning_msg, 'warning')
    else:
        flash(success_msg, 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>', methods=['GET'])
@login_required
def admin_get_user(user_id):
    if not current_user_has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    u = User.query.get_or_404(user_id)
    if u.role == 'patient':
        return jsonify({'error': 'Patient profiles are managed in the Patients module'}), 403
    try:
        doctor_profile = Doctor.query.filter_by(user_id=u.id).first()
        projected_user = build_user_profile_projection(u, viewer=current_user, include_sensitive=True)
        return jsonify({
            'id': projected_user.get('id'),
            'username': projected_user.get('username'),
            'first_name': projected_user.get('first_name'),
            'last_name': projected_user.get('last_name'),
            'email': projected_user.get('email'),
            'phone': projected_user.get('phone'),
            'department': getattr(u, 'department', None),
            'job_category': getattr(u, 'job_category', None),
            'bank_account': getattr(u, 'bank_account', None),
            'bank_name': getattr(u, 'bank_name', None),
            'bank_account_type': getattr(u, 'bank_account_type', None),
            'preferred_payment_method': getattr(u, 'preferred_payment_method', None),
            'role': projected_user.get('role'),
            'account_role': getattr(u, 'account_role', None),
            'staff_group': getattr(u, 'staff_group', None),
            'practitioner_type': getattr(u, 'practitioner_type', None),
            'professional_title': getattr(u, 'professional_title', None),
            'specialization': doctor_profile.specialization if doctor_profile else None,
            'license_number': doctor_profile.license_number if doctor_profile else None,
            'license_regulatory_body': getattr(doctor_profile, 'license_regulatory_body', None) if doctor_profile else None,
            'license_issue_date': doctor_profile.license_issue_date.isoformat() if doctor_profile and doctor_profile.license_issue_date else None,
            'license_expiry_date': doctor_profile.license_expiry_date.isoformat() if doctor_profile and doctor_profile.license_expiry_date else None,
            'license_renewal_status': getattr(doctor_profile, 'license_renewal_status', None) if doctor_profile else None,
            'qualifications': doctor_profile.qualifications if doctor_profile else None,
            'awards_merits': getattr(doctor_profile, 'awards_merits', None) if doctor_profile else None,
            'consultation_fee': doctor_profile.consultation_fee if doctor_profile else None,
            'public_profile_visible': bool(getattr(u, 'public_profile_visible', False)),
            'public_show_consultation_fee': bool(getattr(u, 'public_show_consultation_fee', False)),
            'show_availability': bool(getattr(u, 'show_availability', True)),
            'share_data': bool(getattr(u, 'share_data', False)),
            'email_verified': bool(getattr(u, 'email_verified', False)),
            'is_active': bool(u.is_active)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/users_data', methods=['GET'])
@login_required
def admin_users_data():
    """Return users as JSON for admin user management filters."""
    if not current_user_has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403

    role = request.args.get('role')
    status = request.args.get('status')
    search = (request.args.get('search') or '').strip()
    staff_group = (request.args.get('staff_group') or '').strip()
    practitioner_type = (request.args.get('practitioner_type') or '').strip()
    public_profile = (request.args.get('public_profile') or '').strip()

    query = User.query.filter(User.role != 'patient')
    if role and role != 'patient':
        query = query.filter(User.role == role)
    elif role == 'patient':
        return jsonify({'users': []})
    if status:
        if status == 'active':
            query = query.filter(User.is_active == True)
        elif status == 'inactive':
            query = query.filter(User.is_active == False)
    if search:
        from sqlalchemy import or_
        if '@' in search:
            query = query.filter(User.email_hash == _hash_value(search))
        else:
            query = query.filter(
                or_(
                    User.username.ilike(f"%{search}%"),
                    User.first_name.ilike(f"%{search}%"),
                    User.last_name.ilike(f"%{search}%")
                )
            )
    if staff_group:
        query = query.filter(User.staff_group == staff_group)
    if practitioner_type:
        query = query.filter(User.practitioner_type == practitioner_type)
    if public_profile == 'visible':
        query = query.filter(User.public_profile_visible == True)
    elif public_profile == 'hidden':
        query = query.filter(User.public_profile_visible == False)

    users = query.order_by(User.created_at.desc()).all()
    out = []
    for u in users:
        try:
            projected_user = build_user_profile_projection(u, viewer=current_user, include_sensitive=True)
            out.append({
                'id': projected_user.get('id'),
                'username': projected_user.get('username'),
                'first_name': projected_user.get('first_name'),
                'last_name': projected_user.get('last_name'),
                'email': projected_user.get('email'),
                'phone': projected_user.get('phone'),
                'role': projected_user.get('role'),
                'account_role': getattr(u, 'account_role', None),
                'staff_group': getattr(u, 'staff_group', None),
                'practitioner_type': getattr(u, 'practitioner_type', None),
                'professional_title': getattr(u, 'professional_title', None),
                'department': getattr(u, 'department', None),
                'job_category': getattr(u, 'job_category', None),
                'public_profile_visible': bool(getattr(u, 'public_profile_visible', False)),
                'public_show_consultation_fee': bool(getattr(u, 'public_show_consultation_fee', False)),
                'profile_picture_url': get_user_profile_picture_url(u),
                'email_verified': bool(getattr(u, 'email_verified', False)),
                'is_active': bool(u.is_active),
                'created_at': u.created_at.isoformat() if u.created_at else None
            })
        except Exception:
            # If decryption fails for a field, continue with raw values where possible
            out.append({
                'id': u.id,
                'username': getattr(u, 'username', ''),
                'first_name': getattr(u, 'encrypted_first_name', '') if getattr(u, 'encrypted_first_name', None) else '',
                'last_name': getattr(u, 'encrypted_last_name', '') if getattr(u, 'encrypted_last_name', None) else '',
                'email': None,
                'phone': None,
                'role': getattr(u, 'role', ''),
                'account_role': getattr(u, 'account_role', None),
                'staff_group': getattr(u, 'staff_group', None),
                'practitioner_type': getattr(u, 'practitioner_type', None),
                'professional_title': getattr(u, 'professional_title', None),
                'department': getattr(u, 'department', None),
                'job_category': getattr(u, 'job_category', None),
                'public_profile_visible': bool(getattr(u, 'public_profile_visible', False)),
                'public_show_consultation_fee': bool(getattr(u, 'public_show_consultation_fee', False)),
                'profile_picture_url': get_user_profile_picture_url(u),
                'email_verified': bool(getattr(u, 'email_verified', False)),
                'is_active': bool(getattr(u, 'is_active', False)),
                'created_at': u.created_at.isoformat() if getattr(u, 'created_at', None) else None
            })

    return jsonify({'users': out})


@app.route('/admin/update_user', methods=['POST'])
@login_required
def admin_update_user():
    if not current_user_has_role('admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    data = request.form or request.get_json() or {}
    try:
        uid = int(data.get('user_id'))
    except Exception:
        return jsonify({'success': False, 'error': 'Missing user_id'}), 400

    u = User.query.get_or_404(uid)
    if u.role == 'patient':
        return jsonify({'success': False, 'error': 'Patient profiles are managed in the Patients module'}), 403

    username = data.get('username')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone = data.get('phone')
    department = (data.get('department') or '').strip() or None
    job_category = (data.get('job_category') or '').strip() or None
    bank_account = (data.get('bank_account') or '').strip() or None
    bank_name = (data.get('bank_name') or '').strip() or None
    bank_account_type = (data.get('bank_account_type') or '').strip() or None
    preferred_payment_method = (data.get('preferred_payment_method') or '').strip() or None
    email_verified = parse_bool_flag(data.get('email_verified'), default=False)
    public_profile_visible = parse_bool_flag(data.get('public_profile_visible'), default=False)
    public_show_consultation_fee = parse_bool_flag(data.get('public_show_consultation_fee'), default=False)
    show_availability = parse_bool_flag(data.get('show_availability'), default=True)
    share_data = parse_bool_flag(data.get('share_data'), default=False)
    role = data.get('role')
    password = data.get('password')
    staff_group = (data.get('staff_group') or '').strip() or None
    practitioner_type = (data.get('practitioner_type') or '').strip() or None
    professional_title = (data.get('professional_title') or '').strip() or None
    specialization = (data.get('specialization') or '').strip() or None
    license_number = (data.get('license_number') or '').strip() or None
    license_regulatory_body = (data.get('license_regulatory_body') or '').strip() or None
    license_issue_date = parse_iso_date(data.get('license_issue_date'))
    license_expiry_date = parse_iso_date(data.get('license_expiry_date'))
    license_renewal_status = (data.get('license_renewal_status') or '').strip() or None
    qualifications = (data.get('qualifications') or '').strip() or None
    awards_merits = (data.get('awards_merits') or '').strip() or None
    consultation_fee = parse_optional_float(data.get('consultation_fee'))
    otp_challenge_id = (data.get('email_otp_challenge_id') or '').strip()
    otp_verified_flag = (data.get('email_otp_verified', 'false') or '').strip().lower() == 'true'

    # Basic validation
    if not all([username, email, first_name, last_name]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    if role == 'patient':
        return jsonify({'success': False, 'error': 'Patient accounts are managed from the Patients module'}), 400
    if role == 'doctor' and not license_number:
        return jsonify({'success': False, 'error': 'License number is required for practitioner staff'}), 400
    if role != 'doctor' and (staff_group == 'practitioner' or practitioner_type):
        return jsonify({'success': False, 'error': 'Practitioner classification requires doctor role and valid license'}), 400

    # Check username/email uniqueness excluding current user
    exists = User.query.filter(User.username == username, User.id != u.id).first()
    if exists:
        return jsonify({'success': False, 'error': 'Username already taken'}), 400
    if User.query.filter(User.email_hash == _hash_value(email), User.id != u.id).first():
        return jsonify({'success': False, 'error': 'Email already registered'}), 400

    email_changed = (u.email_hash != _hash_value(email))
    email_change_verified = False
    if email_changed and otp_verified_flag:
        challenge, challenge_error = _consume_verified_otp_challenge(email, 'admin_update_user_email', otp_challenge_id, require_admin=True)
        if challenge_error:
            db.session.rollback()
            return jsonify({'success': False, 'error': 'Email OTP verification failed. Verify the new email or save without verification to require user verification at next login.'}), 400
        email_change_verified = True

    try:
        u.username = username
        u.email = email
        if email_changed:
            u.email_verified = True if email_change_verified else False
            u.email_verification_token = None
        u.first_name = first_name
        u.last_name = last_name
        u.phone = phone
        u.department = department
        u.job_category = job_category
        u.bank_account = bank_account
        u.bank_name = bank_name
        u.bank_account_type = bank_account_type
        u.preferred_payment_method = preferred_payment_method
        if not email_changed:
            u.email_verified = email_verified
        u.public_profile_visible = public_profile_visible
        u.public_show_consultation_fee = public_show_consultation_fee
        u.show_availability = show_availability
        u.share_data = share_data
        u.professional_title = professional_title
        # role change handling
        old_role = u.role
        u.role = role
        if role == 'doctor':
            u.account_role = 'staff'
            u.staff_group = 'practitioner'
            u.practitioner_type = practitioner_type or 'general_practitioner'
        elif role == 'admin':
            u.account_role = 'admin'
            u.staff_group = staff_group or 'administration'
            u.practitioner_type = practitioner_type if u.staff_group == 'practitioner' else None
        if password:
            u.set_password(password)

        db.session.add(u)
        db.session.commit()

        # ensure role-specific profile exists
        if role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=u.id).first()
            if not doctor:
                doctor = Doctor(user_id=u.id)
                db.session.add(doctor)
            doctor.specialization = specialization
            doctor.license_number = license_number
            doctor.license_regulatory_body = license_regulatory_body
            doctor.license_issue_date = license_issue_date
            doctor.license_expiry_date = license_expiry_date
            doctor.license_renewal_status = license_renewal_status
            doctor.qualifications = qualifications
            doctor.awards_merits = awards_merits
            doctor.consultation_fee = consultation_fee

        profile_picture_file = request.files.get('profile_picture') if request.files else None
        if profile_picture_file and profile_picture_file.filename:
            uploaded_path = handle_file_upload(u, profile_picture_file, upload_type='profile_pics', encrypt=True)
            if uploaded_path:
                u.profile_picture = uploaded_path
                db.session.add(u)
                if u.role == 'patient':
                    synced_patient = _sync_patient_picture_from_user(u)
                    if synced_patient:
                        db.session.add(synced_patient)
        if role == 'patient' and not Patient.query.filter_by(user_id=u.id).first():
            db.session.add(Patient(user_id=u.id))
        if role == 'patient' and (u.profile_picture_blob or u.profile_picture):
            synced_patient = _sync_patient_picture_from_user(u)
            if synced_patient:
                db.session.add(synced_patient)
        # if role changed away from doctor/patient, we leave legacy records (optional: remove)
        db.session.commit()

        if email_changed and not email_change_verified:
            return jsonify({'success': True, 'user_id': u.id, 'message': 'User updated. New email must be verified at next login or via OTP during edit.'})
        return jsonify({'success': True, 'user_id': u.id, 'message': 'User updated successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/toggle_user_status', methods=['POST'])
@login_required
def admin_toggle_user_status():
    if not current_user_has_role('admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    data = request.form or request.get_json() or {}
    try:
        uid = int(data.get('user_id'))
    except Exception:
        return jsonify({'success': False, 'error': 'Missing user_id'}), 400
    u = User.query.get_or_404(uid)
    try:
        if not bool(u.is_active) and is_practitioner_user(u) and not has_practitioner_license_compliance(u):
            return jsonify({'success': False, 'error': 'Cannot activate practitioner account without valid license compliance'}), 400
        u.is_active = not bool(u.is_active)
        db.session.add(u)
        db.session.commit()
        return jsonify({'success': True, 'user_id': u.id, 'is_active': u.is_active})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/delete_user', methods=['POST'])
@login_required
def admin_delete_user():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    data = request.form or request.get_json() or {}
    try:
        uid = int(data.get('user_id'))
    except Exception:
        return jsonify({'success': False, 'error': 'Missing user_id'}), 400

    if uid == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400

    u = User.query.get_or_404(uid)
    try:
        role = request.args.get('role')
        status = request.args.get('status')
        search = request.args.get('search', '').strip()

        # paging
        try:
            page = int(request.args.get('page', 1))
            if page < 1:
                page = 1
        except Exception:
            page = 1
        try:
            per_page = int(request.args.get('per_page', 25))
            if per_page < 1:
                per_page = 25
        except Exception:
            per_page = 25

        query = User.query
        if role:
            query = query.filter(User.role == role)
        if status:
            if status == 'active':
                query = query.filter(User.is_active == True)
            elif status == 'inactive':
                query = query.filter(User.is_active == False)

        # Search: support username partial matches and exact email (by hashing)
        from sqlalchemy import or_
        if search:
            if '@' in search:
                # treat as email search (exact match via deterministic hash)
                email_hash = _hash_value(search)
                query = query.filter(User.email_hash == email_hash)
            else:
                query = query.filter(or_(User.username.ilike(f"%{search}%")))

        total = query.count()
        users = query.order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

        out = []
        for u in users:
            try:
                projected_user = build_user_profile_projection(u, viewer=current_user, include_sensitive=True)
                out.append({
                    'id': projected_user.get('id'),
                    'username': projected_user.get('username'),
                    'first_name': projected_user.get('first_name'),
                    'last_name': projected_user.get('last_name'),
                    'email': projected_user.get('email'),
                    'phone': projected_user.get('phone'),
                    'role': projected_user.get('role'),
                    'is_active': bool(u.is_active),
                    'created_at': u.created_at.isoformat() if u.created_at else None
                })
            except Exception:
                out.append({
                    'id': u.id,
                    'username': getattr(u, 'username', ''),
                    'first_name': None,
                    'last_name': None,
                    'email': None,
                    'phone': None,
                    'role': getattr(u, 'role', ''),
                    'is_active': bool(getattr(u, 'is_active', False)),
                    'created_at': u.created_at.isoformat() if getattr(u, 'created_at', None) else None
                })

        pages = (total + per_page - 1) // per_page
        return jsonify({'users': out, 'total': total, 'page': page, 'per_page': per_page, 'pages': pages})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# Download communication file (decrypt and stream)
@app.route('/admin/communication/download/<int:comm_id>')
@login_required
def admin_download_communication_file(comm_id):
    comm = Communication.query.get_or_404(comm_id)
    # Only admins or participants should access; here we allow admins
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    # Prefer blob if available
    blob = comm.encrypted_file_blob
    if blob:
        data = decrypt_file_bytes(blob)
        if data is None:
            flash('Unable to decrypt file', 'error')
            apt = db.session.get(Appointment, comm.appointment_id)
            pid = apt.patient_id if apt else None
            return redirect(request.referrer or url_for('admin_view_patient', patient_id=pid))
        # Determine a filename from comm id and type
        filename = f"comm_{comm.id}_{comm.message_type}"
        return send_file(BytesIO(data), download_name=filename, as_attachment=True)

    # Fallback: if encrypted_file_path present, decrypt and serve
    path = comm.file_path if hasattr(comm, 'file_path') else None
    if path:
        # If path is stored as encrypted path, decrypt
        realpath = comm.file_path
        try:
            # Serve file from static if path is relative
            if realpath and (realpath.startswith('profile_pics') or realpath.startswith('uploads') or realpath.startswith('wallpapers')):
                return send_file(os.path.join(app.static_folder, realpath))
        except Exception:
            pass

    flash('No file available', 'error')
    apt = db.session.get(Appointment, comm.appointment_id)
    pid = apt.patient_id if apt else None
    return redirect(request.referrer or url_for('admin_view_patient', patient_id=pid))


# ============================================
# CUSTOMER CARE ROUTES
# ============================================

@app.route('/customer-care/dashboard')
@login_required
def customer_care_dashboard():
    if current_user.role != 'customer_care':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    conversations = SupportConversation.query.filter_by(agent_id=current_user.id).order_by(SupportConversation.updated_at.desc()).all()
    unassigned = SupportConversation.query.filter_by(agent_id=None, status='open').order_by(SupportConversation.created_at.desc()).all()
    return render_template('customer_care/dashboard.html', conversations=conversations, unassigned=unassigned)


@app.route('/api/support/conversations', methods=['GET'])
@login_required
def api_support_conversations():
    """List support conversations for the current user."""
    try:
        if current_user.role == 'customer_care':
            mine = SupportConversation.query.filter_by(agent_id=current_user.id).order_by(SupportConversation.updated_at.desc()).all()
            unassigned = SupportConversation.query.filter_by(agent_id=None, status='open').order_by(SupportConversation.created_at.desc()).all()
            items = [c.to_dict() for c in mine] + [c.to_dict() for c in unassigned]
            # Add user info
            for item in items:
                u = db.session.get(User, item['user_id'])
                item['user_name'] = u.get_display_name() if u else 'Unknown'
                if item['agent_id']:
                    a = db.session.get(User, item['agent_id'])
                    item['agent_name'] = a.get_display_name() if a else 'Unassigned'
                else:
                    item['agent_name'] = 'Unassigned'
                last_msg = SupportMessage.query.filter_by(conversation_id=item['id']).order_by(SupportMessage.created_at.desc()).first()
                item['last_message'] = last_msg.content if last_msg else None
                item['unread_count'] = SupportMessage.query.filter_by(conversation_id=item['id'], is_read=False).filter(SupportMessage.sender_id != current_user.id).count()
        elif current_user.role == 'admin':
            convos = SupportConversation.query.order_by(SupportConversation.updated_at.desc()).limit(200).all()
            items = []
            for c in convos:
                d = c.to_dict()
                u = db.session.get(User, c.user_id)
                d['user_name'] = u.get_display_name() if u else 'Unknown'
                d['agent_name'] = (db.session.get(User, c.agent_id).get_display_name() if c.agent_id else 'Unassigned')
                items.append(d)
        else:
            convos = SupportConversation.query.filter_by(user_id=current_user.id).order_by(SupportConversation.updated_at.desc()).all()
            items = []
            for c in convos:
                d = c.to_dict()
                d['agent_name'] = (db.session.get(User, c.agent_id).get_display_name() if c.agent_id else 'Customer Care')
                last_msg = SupportMessage.query.filter_by(conversation_id=c.id).order_by(SupportMessage.created_at.desc()).first()
                d['last_message'] = last_msg.content if last_msg else None
                d['unread_count'] = SupportMessage.query.filter_by(conversation_id=c.id, is_read=False).filter(SupportMessage.sender_id != current_user.id).count()
                items.append(d)
        return jsonify({'conversations': items})
    except Exception as e:
        app.logger.exception('api_support_conversations error: %s', e)
        return jsonify({'conversations': []}), 200


@app.route('/api/support/conversations', methods=['POST'])
@login_required
def api_support_create_conversation():
    """Create a new support conversation (any user can open one)."""
    try:
        data = request.get_json(silent=True) or {}
        subject = (data.get('subject') or 'General Support').strip()[:255]
        message_text = (data.get('message') or '').strip()
        if not message_text:
            return jsonify({'error': 'Message is required'}), 400
        # Check for existing open conversation by this user
        existing = SupportConversation.query.filter_by(user_id=current_user.id, status='open').first()
        if not existing:
            existing = SupportConversation.query.filter_by(user_id=current_user.id, status='assigned').first()
        if existing:
            conv = existing
        else:
            conv = SupportConversation(user_id=current_user.id, subject=subject, status='open')
            db.session.add(conv)
            db.session.flush()
        msg = SupportMessage(conversation_id=conv.id, sender_id=current_user.id, message_type='text')
        msg.content = message_text
        db.session.add(msg)
        db.session.commit()
        # Notify customer care agents via socket
        socketio.emit('new_support_message', {
            'conversation_id': conv.id,
            'user_id': current_user.id,
            'user_name': current_user.get_display_name(),
            'message': message_text,
            'subject': conv.subject,
        }, room='role_customer_care')
        return jsonify({'conversation': conv.to_dict(), 'message': msg.to_dict()})
    except Exception as e:
        db.session.rollback()
        app.logger.exception('api_support_create_conversation error: %s', e)
        return jsonify({'error': 'Server error'}), 500


@app.route('/api/support/conversations/<int:conv_id>/messages', methods=['GET'])
@login_required
def api_support_messages(conv_id):
    """Get messages for a support conversation."""
    try:
        conv = db.session.get(SupportConversation, conv_id)
        if not conv:
            return jsonify({'error': 'Not found'}), 404
        if current_user.role not in ('admin', 'customer_care') and conv.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        msgs = SupportMessage.query.filter_by(conversation_id=conv_id).order_by(SupportMessage.created_at.asc()).all()
        # Mark unread messages as read
        SupportMessage.query.filter_by(conversation_id=conv_id, is_read=False).filter(SupportMessage.sender_id != current_user.id).update({'is_read': True})
        db.session.commit()
        items = []
        for m in msgs:
            d = m.to_dict()
            sender = db.session.get(User, m.sender_id)
            d['sender_name'] = sender.get_display_name() if sender else 'Unknown'
            d['sender_role'] = sender.role if sender else 'unknown'
            items.append(d)
        return jsonify({'messages': items, 'conversation': conv.to_dict()})
    except Exception as e:
        app.logger.exception('api_support_messages error: %s', e)
        return jsonify({'messages': []}), 200


@app.route('/api/support/conversations/<int:conv_id>/messages', methods=['POST'])
@login_required
def api_support_send_message(conv_id):
    """Send a message in a support conversation."""
    try:
        conv = db.session.get(SupportConversation, conv_id)
        if not conv:
            return jsonify({'error': 'Not found'}), 404
        if current_user.role not in ('admin', 'customer_care') and conv.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        data = request.get_json(silent=True) or {}
        message_text = (data.get('message') or '').strip()
        if not message_text:
            return jsonify({'error': 'Message is required'}), 400
        msg = SupportMessage(conversation_id=conv.id, sender_id=current_user.id, message_type='text')
        msg.content = message_text
        db.session.add(msg)
        conv.updated_at = now_eat()
        db.session.commit()
        msg_data = msg.to_dict()
        msg_data['sender_name'] = current_user.get_display_name()
        msg_data['sender_role'] = current_user.role
        # Notify the other party
        if current_user.role in ('customer_care', 'admin'):
            socketio.emit('new_support_message', msg_data, room=f'user_{conv.user_id}')
        else:
            socketio.emit('new_support_message', msg_data, room='role_customer_care')
            if conv.agent_id:
                socketio.emit('new_support_message', msg_data, room=f'user_{conv.agent_id}')
        return jsonify({'message': msg_data})
    except Exception as e:
        db.session.rollback()
        app.logger.exception('api_support_send_message error: %s', e)
        return jsonify({'error': 'Server error'}), 500


@app.route('/api/support/conversations/<int:conv_id>/assign', methods=['POST'])
@login_required
def api_support_assign(conv_id):
    """Customer care agent picks up / assigns a conversation to themselves."""
    if current_user.role not in ('customer_care', 'admin'):
        return jsonify({'error': 'Access denied'}), 403
    try:
        conv = db.session.get(SupportConversation, conv_id)
        if not conv:
            return jsonify({'error': 'Not found'}), 404
        conv.agent_id = current_user.id
        conv.status = 'assigned'
        db.session.commit()
        return jsonify({'conversation': conv.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500


@app.route('/api/support/conversations/<int:conv_id>/close', methods=['POST'])
@login_required
def api_support_close(conv_id):
    """Close a support conversation."""
    if current_user.role not in ('customer_care', 'admin'):
        return jsonify({'error': 'Access denied'}), 403
    try:
        conv = db.session.get(SupportConversation, conv_id)
        if not conv:
            return jsonify({'error': 'Not found'}), 404
        conv.status = 'closed'
        conv.closed_at = now_eat()
        db.session.commit()
        socketio.emit('support_conversation_closed', {'conversation_id': conv.id}, room=f'user_{conv.user_id}')
        return jsonify({'conversation': conv.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Server error'}), 500


@app.route('/support/call/<int:conv_id>')
@login_required
def support_call(conv_id):
    """Simple support voice/video call page for customer care conversations."""
    conv = db.session.get(SupportConversation, conv_id)
    if not conv:
        flash('Conversation not found', 'error')
        return redirect(url_for('index'))
    # Only the user and the assigned agent (or any customer_care/admin) can join
    if current_user.id != conv.user_id and current_user.role not in ('customer_care', 'admin'):
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    other_user = None
    if current_user.id == conv.user_id:
        other_user = db.session.get(User, conv.agent_id) if conv.agent_id else None
    else:
        other_user = db.session.get(User, conv.user_id)
    return render_template('customer_care/support_call.html',
                           conv=conv,
                           other_user=other_user,
                           room_id=f'support_call_{conv_id}')


# Communication Routes
@app.route('/communication/<int:appointment_id>')
@login_required
def communication_dashboard(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)

    # Check if user has access to this appointment
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            flash('Access denied', 'error')
            return redirect(url_for('patient_dashboard'))
        # Load all appointments for this patient
        appointments = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.appointment_date.desc()).all()
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if appointment.doctor_id != doctor.id:
            flash('Access denied', 'error')
            return redirect(url_for('doctor_dashboard'))
        # Load all appointments for this doctor
        appointments = Appointment.query.filter_by(doctor_id=doctor.id).order_by(Appointment.appointment_date.desc()).all()
    else:
        appointments = []

    # Check payment status for this appointment
    from models import Payment
    payment = Payment.query.filter_by(appointment_id=appointment_id).order_by(Payment.created_at.desc()).first()
    payment_required = False
    payment_url = None
    if payment is None or payment.status != 'paid':
        # For patients, require payment before enabling communication features
        if current_user.role == 'patient':
            payment_required = True
            if payment:
                payment_url = url_for('payment_page', payment_id=payment.id)
            else:
                # create a placeholder payment pointing to appointment
                try:
                    p = Payment(appointment_id=appointment.id, patient_id=patient.id)
                    db.session.add(p)
                    db.session.commit()
                    payment_url = url_for('payment_page', payment_id=p.id)
                except Exception:
                    payment_url = url_for('patient_appointment')

    # Load recent messages for this appointment (limit to last 200 to avoid large queries)
    try:
        messages = Communication.query.filter_by(
            appointment_id=appointment_id
        ).order_by(Communication.timestamp.desc()).limit(200).all()
        # reverse so template receives chronological order (oldest first)
        messages = list(reversed(messages))
    except Exception:
        # fallback to safe query if something goes wrong
        messages = Communication.query.filter_by(appointment_id=appointment_id).order_by(Communication.timestamp).all()

    # Load prescriptions for this appointment (for doctor prescription send panel)
    prescriptions = []
    if current_user.role == 'doctor':
        try:
            prescriptions = Prescription.query.filter_by(appointment_id=appointment_id).order_by(Prescription.created_at.desc()).all()
        except Exception:
            prescriptions = []

    return render_template('communication/communication_dashboard_new.html',
                         appointment=appointment,
                         appointments=appointments,
                         messages=messages,
                         prescriptions=prescriptions,
                         payment_required=payment_required,
                         payment_url=payment_url)


# Payment pages and APIs
@app.route('/payment/<int:payment_id>')
@login_required
def payment_page(payment_id):
    from models import Payment
    payment = Payment.query.get_or_404(payment_id)
    # Only patient who owns payment or admin may view
    patient = db.session.get(Patient, payment.patient_id)
    if current_user.role == 'patient' and patient.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    return render_template('payment/payment_page.html', payment=payment)


@app.route('/payment/status/<int:payment_id>')
@login_required
def payment_status(payment_id):
    from models import Payment
    payment = Payment.query.get_or_404(payment_id)
    return jsonify({'id': payment.id, 'status': payment.status, 'provider': payment.provider, 'amount': payment.amount})


def _can_view_sensitive_profile(viewer, target_user):
    if viewer is None or target_user is None:
        return False
    return viewer.role == 'admin' or viewer.id == target_user.id


def is_practitioner_user(user):
    if user is None:
        return False
    role = getattr(user, 'role', None)
    staff_group = getattr(user, 'staff_group', None)
    practitioner_type = getattr(user, 'practitioner_type', None)
    return role == 'doctor' or staff_group == 'practitioner' or bool(practitioner_type)


def has_practitioner_license_compliance(user):
    if not is_practitioner_user(user):
        return True
    try:
        doctor_profile = Doctor.query.filter_by(user_id=user.id).first()
        return bool((getattr(doctor_profile, 'license_number', None) or '').strip())
    except Exception:
        return False


def build_user_profile_projection(target_user, viewer=None, include_sensitive=False):
    doctor_profile = Doctor.query.filter_by(user_id=target_user.id).first() if getattr(target_user, 'role', None) == 'doctor' else None
    license_validity_status = None
    if doctor_profile:
        expiry = getattr(doctor_profile, 'license_expiry_date', None)
        renewal = (getattr(doctor_profile, 'license_renewal_status', None) or '').strip().lower()
        if expiry and expiry < now_eat().date():
            license_validity_status = 'expired'
        elif renewal in ('pending', 'expired', 'suspended', 'invalid'):
            license_validity_status = renewal
        elif getattr(doctor_profile, 'license_number', None):
            license_validity_status = 'valid'

    profile_data = {
        'id': target_user.id,
        'username': target_user.username,
        'name': target_user.get_display_name(),
        'first_name': target_user.first_name,
        'last_name': target_user.last_name,
        'role': target_user.role,
        'professional_title': getattr(target_user, 'professional_title', None),
        'practitioner_type': getattr(target_user, 'practitioner_type', None),
        'specialization': getattr(doctor_profile, 'specialization', None) if doctor_profile else None,
        'qualifications': getattr(doctor_profile, 'qualifications', None) if doctor_profile else None,
        'awards_merits': getattr(doctor_profile, 'awards_merits', None) if doctor_profile else None,
        'consultation_fee': float(doctor_profile.consultation_fee) if doctor_profile and doctor_profile.consultation_fee is not None and (getattr(target_user, 'public_show_consultation_fee', False) or _can_view_sensitive_profile(viewer, target_user)) else None,
        'license_validity_status': license_validity_status,
        'profile_picture_url': get_user_profile_picture_url(target_user)
    }

    if include_sensitive and _can_view_sensitive_profile(viewer, target_user):
        profile_data.update({
            'email': target_user.email,
            'phone': target_user.phone,
            'bank_account': getattr(target_user, 'bank_account', None),
            'bank_name': getattr(target_user, 'bank_name', None),
            'bank_account_type': getattr(target_user, 'bank_account_type', None),
            'preferred_payment_method': getattr(target_user, 'preferred_payment_method', None)
        })

    return profile_data

@app.route('/api/user/<int:user_id>/profile')
@login_required
def get_user_profile(user_id):
    """Get user profile information including profile picture"""
    user = User.query.get_or_404(user_id)
    
    # Check if current user has permission to view this profile
    if current_user.role != 'admin' and current_user.id != user_id:
        # For doctor-patient relationships, check if they have appointments together
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            patient = Patient.query.filter_by(user_id=user_id).first()
            if not patient or not has_shared_appointment(doctor.id, patient.id):
                return jsonify({'error': 'Access denied'}), 403
        elif current_user.role == 'patient':
            patient = Patient.query.filter_by(user_id=current_user.id).first()
            doctor = Doctor.query.filter_by(user_id=user_id).first()
            if not doctor or not has_shared_appointment(doctor.id, patient.id):
                return jsonify({'error': 'Access denied'}), 403

    include_sensitive = request.args.get('include_sensitive', '').lower() in ('1', 'true', 'yes')
    profile_data = build_user_profile_projection(
        target_user=user,
        viewer=current_user,
        include_sensitive=include_sensitive
    )
    
    return jsonify(profile_data)

def has_shared_appointment(doctor_id, patient_id):
    """Check if doctor and patient have any appointments together"""
    appointment = Appointment.query.filter_by(
        doctor_id=doctor_id,
        patient_id=patient_id
    ).first()
    return appointment is not None

@app.route('/api/appointment/<int:appointment_id>/details')
@login_required
def get_appointment_details_enhanced(appointment_id):
    """Get enhanced appointment details with profile pictures"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if not verify_appointment_access(appointment, current_user):
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = db.session.get(Doctor, appointment.doctor_id)
    doctor_user = db.session.get(User, doctor.user_id) if doctor else None
    patient = db.session.get(Patient, appointment.patient_id)
    patient_user = db.session.get(User, patient.user_id) if patient else None
    
    # Get profile picture URLs
    doctor_profile_picture = get_user_profile_picture_url(doctor_user) if doctor_user else None
    patient_profile_picture = get_user_profile_picture_url(patient_user) if patient_user else None

    payment = Payment.query.filter_by(appointment_id=appointment_id).order_by(Payment.created_at.desc()).first()

    try:
        message_count = Communication.query.filter_by(appointment_id=appointment_id).count()
    except Exception:
        message_count = 0

    try:
        attachment_count = Communication.query.filter_by(appointment_id=appointment_id).filter(
            Communication.message_type.in_(['document', 'image', 'voice_note'])
        ).count()
    except Exception:
        attachment_count = 0

    try:
        prescription_count = Prescription.query.filter_by(appointment_id=appointment_id).count()
    except Exception:
        prescription_count = 0

    try:
        record_count = MedicalRecord.query.filter_by(patient_id=appointment.patient_id).count()
    except Exception:
        record_count = 0

    try:
        latest_call = CallHistory.query.filter_by(appointment_id=appointment_id).order_by(CallHistory.initiated_at.desc()).first()
    except Exception:
        latest_call = None

    try:
        latest_testimonial = Testimonial.query.filter_by(appointment_id=appointment_id).order_by(Testimonial.created_at.desc()).first()
    except Exception:
        latest_testimonial = None
    
    # Check if doctor/patient are online + last seen
    doctor_online = _is_user_online(doctor_user.id) if doctor_user else False
    patient_online = _is_user_online(patient_user.id) if patient_user else False

    def _get_last_seen(uid):
        if not uid:
            return None
        # Try Redis presence first
        presence = _redis_get_json(f'presence:{uid}')
        if presence and presence.get('last_seen'):
            return presence['last_seen']
        # Fallback to in-memory dict
        ls = user_last_seen.get(uid)
        if ls:
            return ls if isinstance(ls, str) else ls.isoformat()
        return None

    doctor_last_seen = _get_last_seen(doctor_user.id) if doctor_user else None
    patient_last_seen = _get_last_seen(patient_user.id) if patient_user else None

    payment_status = get_appointment_payment_status_internal(appointment_id)
    counterpart_user_id = patient_user.id if current_user.role == 'doctor' and patient_user else doctor_user.id if doctor_user else None

    def serialize_call_member(user_row, role_label, default_selected=False, mode='participant'):
        if not user_row:
            return None
        try:
            user_id = int(user_row.id)
        except Exception:
            return None

        profile_url = None
        try:
            if user_row.profile_picture:
                if user_row.profile_picture.startswith('http'):
                    profile_url = user_row.profile_picture
                else:
                    profile_url = url_for('profile_picture', user_id=user_id, _external=True)
        except Exception:
            profile_url = None

        return {
            'user_id': user_id,
            'display_name': safe_display_name(user_row),
            'role': role_label,
            'mode': mode,
            'online': _is_user_online(user_id),
            'profile_picture': profile_url,
            'default_selected': bool(default_selected),
            'is_current_user': user_id == int(current_user.id),
        }

    available_call_participants = []
    if doctor_user:
        available_call_participants.append(
            serialize_call_member(
                doctor_user,
                'doctor',
                default_selected=current_user.role == 'admin',
            )
        )
    if patient_user:
        available_call_participants.append(
            serialize_call_member(
                patient_user,
                'patient',
                default_selected=current_user.role == 'admin',
            )
        )
    available_call_participants = [member for member in available_call_participants if member]

    if current_user.role == 'doctor':
        for member in available_call_participants:
            if member['user_id'] == int(current_user.id):
                member['default_selected'] = False
            elif member['role'] == 'patient':
                member['default_selected'] = True
    elif current_user.role == 'patient':
        for member in available_call_participants:
            if member['user_id'] == int(current_user.id):
                member['default_selected'] = False
            elif member['role'] == 'doctor':
                member['default_selected'] = True

    available_call_observers = []
    if current_user.role in ('doctor', 'admin'):
        try:
            appointment_user_ids = {member['user_id'] for member in available_call_participants}
            for admin_user in User.query.filter_by(role='admin').order_by(User.first_name.asc(), User.last_name.asc()).all():
                admin_entry = serialize_call_member(admin_user, 'admin', default_selected=False, mode='observer')
                if not admin_entry:
                    continue
                if admin_entry['user_id'] == int(current_user.id) or admin_entry['user_id'] in appointment_user_ids:
                    continue
                available_call_observers.append(admin_entry)
        except Exception:
            available_call_observers = []

    default_call_participant_ids = [
        member['user_id']
        for member in available_call_participants
        if member.get('default_selected') and not member.get('is_current_user')
    ]

    return jsonify({
        'id': appointment.id,
        'doctor_id': doctor.id if doctor else None,
        'doctor_user_id': doctor_user.id if doctor_user else None,
        'doctor_first_name': doctor_user.first_name if doctor_user else '',
        'doctor_last_name': doctor_user.last_name if doctor_user else '',
        'doctor_specialization': doctor.specialization if doctor else '',
        'doctor_profile_picture': doctor_profile_picture,
        'doctor_online': doctor_online,
        'doctor_last_seen': doctor_last_seen,
        'patient_id': patient.id if patient else None,
        'patient_user_id': patient_user.id if patient_user else None,
        'patient_first_name': patient_user.first_name if patient_user else '',
        'patient_last_name': patient_user.last_name if patient_user else '',
        'patient_profile_picture': patient_profile_picture,
        'patient_online': patient_online,
        'patient_last_seen': patient_last_seen,
        'counterpart_user_id': counterpart_user_id,
        'appointment_date': appointment.appointment_date.isoformat(),
        'consultation_type': appointment.consultation_type,
        'urgency': appointment.urgency,
        'symptoms': appointment.symptoms,
        'notes': appointment.notes,
        'feedback': appointment.feedback,
        'status': appointment.status,
        'call_status': appointment.call_status,
        'payment_status': payment_status,
        'payment': {
            'status': payment_status,
            'amount': getattr(payment, 'amount', None) if payment else appointment.payment_amount,
            'currency': getattr(payment, 'currency', None) if payment else None,
            'method': getattr(payment, 'payment_method', None) if payment else appointment.payment_method,
            'paid_at': payment.created_at.isoformat() if payment and getattr(payment, 'created_at', None) else appointment.payment_date.isoformat() if appointment.payment_date else None,
            'reminder_sent': getattr(appointment, 'reminder_sent', None)
        },
        'available_call_participants': available_call_participants,
        'available_call_observers': available_call_observers,
        'default_call_participant_ids': default_call_participant_ids,
        'default_call_observer_ids': [],
        'counts': {
            'messages': message_count,
            'attachments': attachment_count,
            'prescriptions': prescription_count,
            'records': record_count
        },
        'latest_call': latest_call.to_dict() if latest_call else None,
        'testimonial': {
            'id': latest_testimonial.id,
            'rating': latest_testimonial.rating,
            'content': latest_testimonial.content,
            'created_at': latest_testimonial.created_at.isoformat() if latest_testimonial.created_at else None
        } if latest_testimonial else None,
        'patient_context': {
            'age': patient_user.age if patient_user else None,
            'medical_history': patient.medical_history if patient else None,
            'allergies': patient.allergies if patient else None,
            'current_medications': patient.current_medications if patient else None,
            'blood_type': patient.blood_type if patient else None,
            'insurance_provider': patient.insurance_provider if patient else None,
            'emergency_contact': patient.emergency_contact if patient else None
        },
        'actions': {
            'can_start_call': payment_status == 'paid',
            'can_send_payment_reminder': current_user.role in ['doctor', 'admin'] and payment_status != 'paid',
            'can_complete': current_user.role == 'doctor' and doctor_user and current_user.id == doctor_user.id and appointment.status != 'completed',
            'can_prescribe': current_user.role == 'doctor' and doctor_user and current_user.id == doctor_user.id,
            'can_leave_testimonial': current_user.role == 'patient' and appointment.status == 'completed' and latest_testimonial is None,
            'can_view_testimonial': latest_testimonial is not None
        },
        'doctor_average_rating': doctor.average_rating if doctor else None
    })

def get_appointment_payment_status_internal(appointment_id):
    """Internal function to get payment status"""
    payment = Payment.query.filter_by(appointment_id=appointment_id).order_by(Payment.created_at.desc()).first()
    if payment:
        return payment.status
    return 'pending'

# Add this route for appointment confirmation
@app.route('/api/appointment/<int:appointment_id>/confirm', methods=['POST'])
@login_required
@csrf.exempt
def confirm_appointment(appointment_id):
    """Confirm an appointment"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        appointment.status = 'confirmed'
        db.session.commit()
        
        # Emit socket event for real-time updates
        if SOCKETIO_AVAILABLE:
            socketio.emit('appointment_status_updated', {
                'appointment_id': appointment.id,
                'status': 'confirmed',
                'patient_id': appointment.patient_id
            })
        
        return jsonify({'success': True, 'message': 'Appointment confirmed successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this route for appointment cancellation
@app.route('/api/appointment/<int:appointment_id>/cancel', methods=['POST'])
@login_required
@csrf.exempt
def cancel_appointment(appointment_id):
    """Cancel an appointment"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        appointment.status = 'cancelled'
        db.session.commit()
        _send_appointment_outcome_email(appointment, outcome='cancelled')
        
        # Emit socket event for real-time updates
        if SOCKETIO_AVAILABLE:
            socketio.emit('appointment_status_updated', {
                'appointment_id': appointment.id,
                'status': 'cancelled',
                'patient_id': appointment.patient_id
            })
        
        return jsonify({'success': True, 'message': 'Appointment cancelled successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this route for appointment rating
@app.route('/api/appointment/<int:appointment_id>/rate', methods=['POST'])
@login_required
@csrf.exempt
def rate_appointment(appointment_id):
    """Rate a completed appointment"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access and that appointment is completed
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if appointment.status != 'completed':
        return jsonify({'success': False, 'error': 'Can only rate completed appointments'}), 400
    
    data = request.get_json()
    rating = data.get('rating')
    comment = data.get('comment', '')
    
    if not rating or not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify({'success': False, 'error': 'Invalid rating'}), 400
    
    try:
        # Update appointment with rating
        appointment.rating = rating
        if comment:
            appointment.feedback = comment
        
        db.session.commit()
        _send_appointment_outcome_email(appointment, outcome='completed')
        
        return jsonify({'success': True, 'message': 'Rating submitted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Update the payment confirmation route to fix CSRF issues
@app.route('/payment/confirm/<int:payment_id>', methods=['POST'])
@login_required
@csrf.exempt  # Remove CSRF for payment confirmations since they come from external sources
def payment_confirm(payment_id):
    """Confirm payment and redirect to patient dashboard"""
    from models import Payment
    payment = Payment.query.get_or_404(payment_id)
    
    # Verify the current user owns this payment
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if payment.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        previous_status = (payment.status or '').strip().lower()
        payment.status = 'paid'
        appointment = db.session.get(Appointment, payment.appointment_id)
        if appointment:
            if appointment.status == 'pending':
                appointment.status = 'confirmed'
            appointment.payment_status = 'paid'
            appointment.payment_date = now_eat()
            if not appointment.payment_amount and getattr(payment, 'amount', None) is not None:
                appointment.payment_amount = float(payment.amount)
            if not appointment.payment_method:
                appointment.payment_method = 'Online'
        db.session.commit()

        if previous_status != 'paid' and appointment:
            _send_later_payment_email(appointment, payment=payment)
        
        # Emit payment status update via Socket.IO
        if SOCKETIO_AVAILABLE:
            socketio.emit('payment_status_updated', {
                'appointment_id': payment.appointment_id,
                'status': 'paid',
                'user_id': current_user.id
            })
        
        return jsonify({'success': True, 'message': 'Payment completed successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this route for payment page by appointment
@app.route('/payment/appointment/<int:appointment_id>')
@login_required
def payment_by_appointment(appointment_id):
    """Payment page for a specific appointment"""
    from models import Payment
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if appointment.patient_id != patient.id:
            flash('Access denied', 'error')
            return redirect(url_for('patient_dashboard'))
    
    # Find or create payment for this appointment
    payment = Payment.query.filter_by(appointment_id=appointment_id).first()
    if not payment:
        # Create a new payment
        doctor = db.session.get(Doctor, appointment.doctor_id)
        amount = doctor.consultation_fee if doctor and doctor.consultation_fee else 1500.00
        
        payment = Payment(
            appointment_id=appointment_id,
            patient_id=appointment.patient_id,
            amount=amount,
            currency='KES',
            status='pending'
        )
        db.session.add(payment)
        db.session.commit()
    
    return render_template('payment/payment_page.html', payment=payment)

# Update the book appointment API to include appointment confirmation
@app.route('/api/book_appointment', methods=['POST'])
@login_required
@csrf.exempt
def book_appointment():
    """Book a new appointment with initial pending status"""
    try:
        if current_user.role != 'patient':
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        print(f"Received booking data: {data}")  # Debug log
        
        # Validate required fields
        required_fields = ['doctor_id', 'date', 'consultation_type', 'symptoms']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({'success': False, 'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            return jsonify({'success': False, 'error': 'Patient profile not found'}), 404
        
        # Parse date with better error handling
        try:
            appointment_date_str = data.get('date')
            print(f"Parsing date: {appointment_date_str}")  # Debug log
            appointment_date = datetime.strptime(appointment_date_str, '%Y-%m-%dT%H:%M')
        except ValueError as e:
            print(f"Date parsing error: {e}")  # Debug log
            return jsonify({'success': False, 'error': f'Invalid date format. Use YYYY-MM-DDTHH:MM. Error: {str(e)}'}), 400
        
        # Check if doctor exists
        doctor = db.session.get(Doctor, data.get('doctor_id'))
        if not doctor:
            return jsonify({'success': False, 'error': 'Doctor not found'}), 404
        
        print(f"Creating appointment for patient {patient.id}, doctor {doctor.id}")  # Debug log
        
        # Create appointment with pending status
        appointment = Appointment(
            patient_id=patient.id,
            doctor_id=data.get('doctor_id'),
            appointment_date=appointment_date,
            consultation_type=data.get('consultation_type'),
            symptoms=data.get('symptoms'),
            status='pending',  # Set to pending until confirmed by patient
            urgency=data.get('urgency', 'routine')
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        print(f"Appointment created with ID: {appointment.id}")  # Debug log

        # Create payment intent
        try:
            amount = float(doctor.consultation_fee) if doctor and doctor.consultation_fee is not None else 1500.00

            payment = Payment(
                appointment_id=appointment.id,
                patient_id=patient.id,
                amount=amount,
                currency='KES',
                status='pending'
            )
            db.session.add(payment)
            appointment.payment_amount = amount
            appointment.payment_status = 'unpaid'
            db.session.commit()

            _send_booking_workflow_email(appointment, payment=payment)

            payment_url = url_for('payment_by_appointment', appointment_id=appointment.id, _external=False)

            return jsonify({
                'success': True, 
                'appointment_id': appointment.id, 
                'payment_url': payment_url, 
                'payment_id': payment.id,
                'message': 'Appointment booked successfully. Please complete payment and confirmation.'
            }), 201
            
        except Exception as e:
            print(f"Payment creation error: {e}")  # Debug log
            try:
                _send_booking_workflow_email(appointment, payment=None)
            except Exception:
                pass
            # If payment creation fails, still return appointment id
            return jsonify({
                'success': True, 
                'appointment_id': appointment.id, 
                'warning': 'Payment creation failed', 
                'error': str(e)
            }), 201
            
    except Exception as e:
        db.session.rollback()
        print(f"Booking error: {e}")  # Debug log
        import traceback
        traceback.print_exc()  # This will print the full traceback to the console
        return jsonify({'success': False, 'error': f'Internal server error: {str(e)}'}), 500

@app.route('/payment/simulate/<int:payment_id>')
@login_required
def simulate_provider(payment_id):
    """Simulated payment provider page (for testing)"""
    from models import Payment
    payment = Payment.query.get_or_404(payment_id)
    
    # Render a simulated payment page that works within modal
    csrf_token = generate_csrf_token()
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Simulated Payment - MAKOKHA MEDICAL CENTRE</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            body {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .payment-sim-card {{
                background: white;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="payment-sim-card p-4">
                        <div class="text-center mb-4">
                            <i class="fas fa-shield-alt fa-3x text-primary mb-3"></i>
                            <h3>Simulated Payment Gateway</h3>
                            <p class="text-muted">Development Environment</p>
                        </div>
                        
                        <div class="card border-0 bg-light mb-4">
                            <div class="card-body">
                                <h5 class="card-title">Payment Details</h5>
                                <div class="d-flex justify-content-between mb-2">
                                    <span>Amount:</span>
                                    <strong>{payment.amount} {payment.currency}</strong>
                                </div>
                                <div class="d-flex justify-content-between mb-2">
                                    <span>Appointment ID:</span>
                                    <strong>#{payment.appointment_id}</strong>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <span>Status:</span>
                                    <span class="badge bg-warning">Pending</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            This is a simulated payment environment for testing purposes.
                        </div>
                        
                        <form method='POST' action='{url_for('payment_confirm', payment_id=payment.id)}'>
                            <input type='hidden' name='csrf_token' value='{csrf_token}'>
                            <div class="d-grid gap-2">
                                <button type='submit' class='btn btn-success btn-lg'>
                                    <i class="fas fa-check me-2"></i>
                                    Simulate Successful Payment
                                </button>
                                <button type='button' class='btn btn-outline-secondary' onclick='window.close()'>
                                    <i class="fas fa-times me-2"></i>
                                    Cancel Payment
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Auto-close after successful payment
            function closeWindow() {{
                setTimeout(() => {{
                    window.close();
                }}, 2000);
            }}
            
            // Handle form submission
            document.querySelector('form').addEventListener('submit', function(e) {{
                e.preventDefault();
                const form = this;
                const submitBtn = form.querySelector('button[type="submit"]');
                const originalText = submitBtn.innerHTML;
                
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
                submitBtn.disabled = true;
                
                fetch(form.action, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/x-www-form-urlencoded',
                    }},
                    body: new URLSearchParams(new FormData(form))
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        submitBtn.innerHTML = '<i class="fas fa-check me-2"></i>Payment Successful!';
                        submitBtn.className = 'btn btn-success btn-lg';
                        setTimeout(() => {{
                            window.close();
                        }}, 1500);
                    }} else {{
                        throw new Error(data.error);
                    }}
                }})
                .catch(error => {{
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                    alert('Payment failed: ' + error.message);
                }});
            }});
        </script>
    </body>
    </html>
    """


# Webhook endpoint for external payment providers (exempt from CSRF)
@app.route('/payment/webhook/<provider>', methods=['POST'])
@csrf.exempt
def payment_webhook(provider):
    """Receive webhook callbacks from external payment providers.

    Example HMAC-SHA256 verification:
    - Provider signs raw request body using a shared secret and sends signature in header `X-Signature`.
    - The application looks up the secret for the provider in `app.config['PAYMENT_PROVIDER_SECRETS']`.
    """
    try:
        secret_map = app.config.get('PAYMENT_PROVIDER_SECRETS', {}) or {}
        secret = secret_map.get(provider)

        raw = request.get_data() or b''

        # Example header name for signature (common patterns vary by provider)
        signature_header = request.headers.get('X-Signature') or request.headers.get('X-Signature-SHA256')

        if secret and signature_header:
            computed = hmac.new(secret.encode('utf-8'), raw, hashlib.sha256).hexdigest()
            # Timing-safe compare
            if not hmac.compare_digest(computed, signature_header):
                return jsonify({'error': 'invalid signature'}), 400

        # Parse JSON payload
        payload = {}
        try:
            payload = request.get_json(force=True)
        except Exception:
            payload = {}

        # Providers may send different payload shapes. Example expected fields:
        # { 'payment_id': 123, 'status': 'paid', 'provider_reference': 'abc123' }
        payment_id = payload.get('payment_id') or payload.get('id') or request.args.get('payment_id')
        status = payload.get('status')
        provider_ref = payload.get('provider_reference') or payload.get('transaction_id')

        if not payment_id:
            return jsonify({'error': 'missing payment_id'}), 400

        from models import Payment
        try:
            try:
                payment = db.session.get(Payment, int(payment_id))
            except Exception:
                payment = None
        except Exception:
            payment = None

        if not payment:
            return jsonify({'error': 'payment not found'}), 404

        previous_status = (payment.status or '').strip().lower()

        # Map provider statuses to our internal states
        if status in ('paid', 'success', 'completed'):
            payment.status = 'paid'
        elif status in ('failed', 'cancelled', 'declined'):
            payment.status = 'failed'
        else:
            # unknown -> store as 'pending' or set provider-specific state
            payment.status = status or payment.status or 'pending'

        if provider_ref:
            payment.provider_reference = provider_ref

        appointment = db.session.get(Appointment, payment.appointment_id) if getattr(payment, 'appointment_id', None) else None
        if appointment and payment.status == 'paid':
            if appointment.status == 'pending':
                appointment.status = 'confirmed'
            appointment.payment_status = 'paid'
            appointment.payment_date = now_eat()
            if not appointment.payment_amount and getattr(payment, 'amount', None) is not None:
                appointment.payment_amount = float(payment.amount)
            if not appointment.payment_method:
                appointment.payment_method = provider or 'Online'

        try:
            db.session.add(payment)
            if appointment:
                db.session.add(appointment)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({'error': 'failed to update payment'}), 500

        if previous_status != 'paid' and payment.status == 'paid' and appointment:
            _send_later_payment_email(appointment, payment=payment)

        # Return 200 to acknowledge webhook
        return jsonify({'ok': True}), 200
    except Exception as e:
        return jsonify({'error': 'exception', 'message': str(e)}), 500


# Stripe-specific webhook handler demonstrating recommended verification
@app.route('/payment/webhook/stripe', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    """Stripe webhook endpoint. Uses official Stripe library if installed.

    Configure `STRIPE_WEBHOOK_SECRET` in `config.py` / env. If the `stripe`
    package is available, we use `stripe.Webhook.construct_event` to verify
    the signature. Otherwise, the endpoint will return 501 indicating the
    stripe library is not available and you should install `stripe`.
    """
    endpoint_secret = app.config.get('STRIPE_WEBHOOK_SECRET')
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')

    if not endpoint_secret:
        return jsonify({'error': 'STRIPE_WEBHOOK_SECRET not configured'}), 500

    try:
        import stripe
    except Exception:
        # Stripe library not installed: advise installation or use generic webhook
        return jsonify({'error': 'stripe library not installed'}), 501

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig_header, secret=endpoint_secret)
    except ValueError:
        return jsonify({'error': 'invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'invalid signature'}), 400

    # Handle relevant event types
    try:
        event_type = event.get('type')
        data_obj = event.get('data', {}).get('object', {})

        if event_type == 'payment_intent.succeeded' or event_type == 'checkout.session.completed':
            # Try to find a payment_id in metadata (recommended to store mapping)
            payment_id = None
            if isinstance(data_obj, dict):
                payment_id = data_obj.get('metadata', {}).get('payment_id') or data_obj.get('id')

            if payment_id:
                from models import Payment
                try:
                    try:
                        payment = db.session.get(Payment, int(payment_id))
                    except Exception:
                        payment = None
                except Exception:
                    payment = None

                if payment:
                    previous_status = (payment.status or '').strip().lower()
                    payment.status = 'paid'
                    payment.provider_reference = data_obj.get('id')
                    appointment = db.session.get(Appointment, payment.appointment_id) if getattr(payment, 'appointment_id', None) else None
                    if appointment:
                        if appointment.status == 'pending':
                            appointment.status = 'confirmed'
                        appointment.payment_status = 'paid'
                        appointment.payment_date = now_eat()
                        if not appointment.payment_amount and getattr(payment, 'amount', None) is not None:
                            appointment.payment_amount = float(payment.amount)
                        if not appointment.payment_method:
                            appointment.payment_method = 'Stripe'
                    try:
                        db.session.add(payment)
                        if appointment:
                            db.session.add(appointment)
                        db.session.commit()
                        if previous_status != 'paid' and appointment:
                            _send_later_payment_email(appointment, payment=payment)
                    except Exception:
                        db.session.rollback()

        # Acknowledge receipt
        return jsonify({'received': True}), 200
    except Exception as e:
        return jsonify({'error': 'processing error', 'message': str(e)}), 500


# Admin view for a single patient's full details
@app.route('/admin/patient/<int:patient_id>')
@login_required
def admin_view_patient(patient_id):
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    patient = Patient.query.options(joinedload(Patient.user)).get_or_404(patient_id)

    # All medical records for the patient
    medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()

    # All appointments for the patient with doctor info
    DoctorUser = aliased(User)
    appts = db.session.query(Appointment, Doctor, DoctorUser).join(Doctor, Appointment.doctor_id == Doctor.id).join(DoctorUser, Doctor.user_id == DoctorUser.id).filter(Appointment.patient_id == patient.id).order_by(Appointment.appointment_date.desc()).all()

    # Communications across all appointments for this patient
    comms = Communication.query.join(Appointment, Communication.appointment_id == Appointment.id).filter(Appointment.patient_id == patient.id).order_by(Communication.timestamp.desc()).all()

    # Files uploaded by doctors or patient (from medical_records) are in medical_records.file_path
    return render_template('admin/patient_detail.html',
                           patient=patient,
                           medical_records=medical_records,
                           appointments=appts,
                           communications=comms)


# Doctor view for a specific patient's medical records
@app.route('/doctor/patient/<int:patient_id>/medical-records')
@login_required
def doctor_patient_medical_records(patient_id):
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    doctor = Doctor.query.filter_by(user_id=current_user.id).first_or_404()
    patient = Patient.query.options(joinedload(Patient.user)).get_or_404(patient_id)

    # Optional: verify that doctor has seen this patient before or allow access
    medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()

    return render_template('doctor/patient_medical_records.html', doctor=doctor, patient=patient, medical_records=medical_records)


# Patient view for their own medical records
@app.route('/patient/medical-records')
@login_required
def patient_medical_records():
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    patient = Patient.query.filter_by(user_id=current_user.id).first_or_404()
    medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()
    return render_template('patient/medical_records.html', patient=patient, medical_records=medical_records)


# API to add a medical record (doctor or patient)
@app.route('/api/medical_record/add', methods=['POST'])
@login_required
@csrf.exempt
def api_add_medical_record():
    # allowed for doctors and patients
    if current_user.role not in ('doctor', 'patient', 'admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    # multipart/form-data expected
    patient_id = request.form.get('patient_id')
    record_type = request.form.get('record_type') or request.form.get('type') or 'general'
    description = request.form.get('description')
    file = request.files.get('file')

    if not patient_id:
        return jsonify({'success': False, 'error': 'patient_id required'}), 400

    patient = db.session.get(Patient, patient_id)
    if not patient:
        return jsonify({'success': False, 'error': 'Patient not found'}), 404

    # If current_user is patient ensure they are adding to their own record
    if current_user.role == 'patient' and patient.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    # Save file if provided
    rel_path = None
    if file and allowed_file(file.filename):
        rel_path = handle_file_upload(current_user, file, upload_type='medical_records', encrypt=True)

    mr = MedicalRecord(patient_id=patient.id, record_type=record_type, created_by=current_user.id)
    if rel_path:
        mr.file_path = rel_path
    if description:
        mr.description = description

    db.session.add(mr)
    db.session.commit()

    # Optionally emit socket event to notify patient/doctor
    return jsonify({'success': True, 'medical_record_id': mr.id})


@app.route('/api/medical_record/<int:record_id>', methods=['GET'])
@login_required
def api_get_medical_record(record_id):
    """Return medical record details as JSON for editing."""
    mr = MedicalRecord.query.get_or_404(record_id)
    # Permission: allow admin, doctor (if assigned/creator), or the patient owner
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or mr.patient_id != patient.id:
            return jsonify({'error': 'Access denied'}), 403
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        patient = db.session.get(Patient, mr.patient_id)
        allowed = False
        if mr.created_by == current_user.id:
            allowed = True
        if doctor and Appointment.query.filter_by(doctor_id=doctor.id, patient_id=patient.id).count() > 0:
            allowed = True
        if not allowed:
            return jsonify({'error': 'Access denied'}), 403
    elif current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    return jsonify({
        'id': mr.id,
        'patient_id': mr.patient_id,
        'record_type': mr.record_type,
        'description': mr.description,
        'has_file': bool(mr.file_path),
        'created_by': mr.created_by,
        'created_at': mr.created_at.isoformat() if mr.created_at else None
    })


# API to update a medical record (description or replace file)
@app.route('/api/medical_record/<int:record_id>/update', methods=['POST'])
@login_required
@csrf.exempt
def api_update_medical_record(record_id):
    mr = MedicalRecord.query.get_or_404(record_id)

    # Only creator, doctor, or admin can update
    if current_user.role not in ('admin', 'doctor') and mr.created_by != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    description = request.form.get('description')
    file = request.files.get('file')

    if description is not None:
        mr.description = description

    if file and allowed_file(file.filename):
        rel_path = handle_file_upload(current_user, file, upload_type='medical_records', encrypt=True)
        if rel_path:
            mr.file_path = rel_path

    db.session.add(mr)
    db.session.commit()
    return jsonify({'success': True})


# API to delete a medical record
@app.route('/api/medical_record/<int:record_id>/delete', methods=['POST'])
@login_required
@csrf.exempt
def api_delete_medical_record(record_id):
    mr = MedicalRecord.query.get_or_404(record_id)
    if current_user.role not in ('admin', 'doctor') and mr.created_by != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    try:
        db.session.delete(mr)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/medical_records/patient/<int:patient_id>', methods=['GET'])
@login_required
def api_get_medical_records_for_patient(patient_id):
    """Return medical records for a patient as JSON. Accessible to patient owner, doctor (if linked), or admin."""
    patient = db.session.get(Patient, patient_id)
    if not patient:
        return jsonify({'error': 'Patient not found'}), 404

    # Authorization
    if current_user.role == 'patient':
        p = Patient.query.filter_by(user_id=current_user.id).first()
        if not p or p.id != patient.id:
            return jsonify({'error': 'Access denied'}), 403
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor:
            return jsonify({'error': 'Doctor profile not found'}), 403
        # ensure doctor has appointments with patient (or allow admin/creator later)
        if Appointment.query.filter_by(doctor_id=doctor.id, patient_id=patient.id).count() == 0:
            return jsonify({'error': 'Access denied'}), 403
    elif current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()
    out = []
    for r in records:
        out.append({
            'id': r.id,
            'record_type': r.record_type,
            'description': r.description,
            'has_file': bool(r.file_path),
            'created_by': r.created_by,
            'created_at': r.created_at.isoformat() if r.created_at else None
        })
    return jsonify({'medical_records': out, 'total': len(out)})

# Duplicate Socket.IO handler removed. The consolidated, non-blocking
# `save_recording` handler is defined earlier in this file and uses a
# background task to perform encryption and DB commits to avoid blocking
# the Socket.IO event loop.


# Profile picture upload (users can upload their own; admin may upload for others)
@app.route('/upload_profile_picture', methods=['POST'])
@login_required
@csrf.exempt
def upload_profile_picture():
    """Upload and encrypt user profile picture, storing in BLOB and with proper directory structure."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Empty filename'}), 400
    
    # Determine target user
    target_user = current_user
    if current_user.role == 'admin' and request.form.get('user_id'):
        try:
            uid = int(request.form.get('user_id'))
            target_user = db.session.get(User, uid) or target_user
        except Exception:
            pass
    
    if file and allowed_file(file.filename):
        # Read file
        raw = file.read()
        try:
            old_user_picture_path = target_user.profile_picture

            # Encrypt file bytes
            encrypted_bytes = encrypt_file_bytes(raw)
            
            # Store encrypted bytes in BLOB column
            target_user.profile_picture_blob = encrypted_bytes
            target_user.profile_picture_mime = file.content_type or 'image/jpeg'
            target_user.profile_picture_name = secure_filename(file.filename)
            
            # Also save to filesystem for reference (uploads/user/{role}/profile_pictures/)
            try:
                rel_root = _uploads_rel_root() or 'uploads'
                user_role = getattr(target_user, 'role', 'user')
                user_id = getattr(target_user, 'id', 'unknown')
                
                # Create directory structure: uploads/user/{role}/profile_pictures/
                rel_dir = os.path.join(rel_root, 'user', user_role, 'profile_pictures').replace('\\', '/')
                full_dir = os.path.join(app.root_path, rel_dir)
                os.makedirs(full_dir, exist_ok=True)
                
                # Generate unique filename
                storage_name = f"{uuid4().hex}__{secure_filename(file.filename)}.enc"
                full_path = os.path.join(full_dir, storage_name)
                rel_path_for_db = os.path.join(rel_dir, storage_name).replace('\\', '/')
                
                # Save encrypted file to disk
                with open(full_path, 'wb') as fh:
                    fh.write(encrypted_bytes)
                
                # Store the file path as backup (encrypted)
                target_user.profile_picture = rel_path_for_db
            except Exception as file_err:
                logging.warning(f"Could not save profile picture to filesystem: {file_err}")
                # Continue anyway since BLOB is stored

            _delete_local_profile_picture_file(old_user_picture_path)

            synced_patient = _sync_patient_picture_from_user(target_user)
            
            db.session.add(target_user)
            if synced_patient:
                db.session.add(synced_patient)
            db.session.commit()
            
            return jsonify({
                'success': True, 
                'user_id': target_user.id,
                'message': 'Profile picture uploaded successfully'
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error uploading profile picture: {e}")
            return jsonify({'success': False, 'error': 'Upload failed', 'detail': str(e)}), 500
    
    return jsonify({'success': False, 'error': 'Invalid file type'}), 400


@app.route('/delete_profile_picture', methods=['POST'])
@login_required
@csrf.exempt
def delete_profile_picture():
    """Delete profile picture for current user, or a target user when requested by admin."""
    target_user = current_user
    if current_user.role == 'admin' and request.form.get('user_id'):
        try:
            uid = int(request.form.get('user_id'))
            target_user = db.session.get(User, uid) or target_user
        except Exception:
            pass

    try:
        old_user_picture_path = target_user.profile_picture
        patient = Patient.query.filter_by(user_id=target_user.id).first()
        old_patient_picture_path = patient.profile_picture if patient else None

        target_user.profile_picture_blob = None
        target_user.profile_picture_mime = None
        target_user.profile_picture_name = None
        target_user.profile_picture = None

        synced_patient = _sync_patient_picture_from_user(target_user, clear=True)

        _delete_local_profile_picture_file(old_user_picture_path)
        _delete_local_profile_picture_file(old_patient_picture_path)

        db.session.add(target_user)
        if synced_patient:
            db.session.add(synced_patient)
        db.session.commit()

        return jsonify({'success': True, 'user_id': target_user.id, 'message': 'Profile picture deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting profile picture: {e}")
        return jsonify({'success': False, 'error': 'Delete failed', 'detail': str(e)}), 500


# Serve decrypted profile picture for a user
@app.route('/profile_picture/<int:user_id>')
def profile_picture(user_id):
    """Serve encrypted profile picture from BLOB or file path, or fallback to SVG avatar."""
    try:
        user = db.session.get(User, user_id)
        if not user:
            return _get_default_avatar('U')

        patient = Patient.query.filter_by(user_id=user.id).first()

        for source in [user, patient]:
            if not source:
                continue

            if getattr(source, 'profile_picture_blob', None):
                try:
                    raw_bytes = decrypt_file_bytes(source.profile_picture_blob)
                    if raw_bytes:
                        mime_type = getattr(source, 'profile_picture_mime', None) or 'image/jpeg'
                        return send_file(BytesIO(raw_bytes), mimetype=mime_type)
                except Exception as dec_err:
                    logging.error(f"Decryption error for profile blob (user {user_id}): {dec_err}")

            pic_path = source.profile_picture
            if pic_path:
                if pic_path.startswith('http'):
                    return redirect(pic_path)

                if pic_path.startswith('blob://'):
                    continue

                try:
                    full_path = os.path.join(app.root_path, pic_path)
                    if os.path.exists(full_path) and os.path.isfile(full_path):
                        with open(full_path, 'rb') as fh:
                            encrypted_bytes = fh.read()
                        try:
                            raw_bytes = decrypt_file_bytes(encrypted_bytes)
                            if raw_bytes:
                                _, ext = os.path.splitext(pic_path)
                                content_type = 'image/jpeg'
                                if ext.lower() in ['.png']:
                                    content_type = 'image/png'
                                elif ext.lower() in ['.gif']:
                                    content_type = 'image/gif'
                                elif ext.lower() in ['.webp']:
                                    content_type = 'image/webp'
                                return send_file(BytesIO(raw_bytes), mimetype=content_type)
                        except Exception as dec_err:
                            logging.error(f"Decryption error for {pic_path}: {dec_err}")
                except Exception as file_err:
                    logging.error(f"File access error for {pic_path}: {file_err}")
        
        # Fallback to SVG avatar with user initials
        return _get_default_avatar(user.get_initials())
        
    except Exception as e:
        logging.error(f"Error serving profile picture for user {user_id}: {e}")
        return _get_default_avatar('E')


def _get_default_avatar(initials='U'):
    """Generate and return a default SVG avatar with given initials."""
    # Use a color based on initial hash for visual variety
    color_map = {
        'A': '#FF6B6B', 'B': '#4ECDC4', 'C': '#45B7D1', 'D': '#FFA07A',
        'E': '#98D8C8', 'F': '#F7DC6F', 'G': '#BB8FCE', 'H': '#85C1E2',
        'I': '#F8B88B', 'J': '#ABEBC6', 'K': '#F5B7B1', 'L': '#D7BDE2',
        'M': '#A9DFBF', 'N': '#F9E79F', 'O': '#AED6F1', 'P': '#F1948A',
        'Q': '#D5F4E6', 'R': '#FADBD8', 'S': '#E8DAEF', 'T': '#A3E4D7',
        'U': '#667eea', 'V': '#764EA2', 'W': '#F093FB', 'X': '#4158D0',
        'Y': '#C471ED', 'Z': '#12C2E9'
    }
    color = color_map.get(initials[0].upper(), '#667eea')
    return f'''
    <svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <circle cx="50" cy="50" r="50" fill="{color}"/>
        <text x="50" y="60" text-anchor="middle" fill="white" font-size="40" font-weight="bold" font-family="Arial">{initials}</text>
    </svg>
    ''', 200, {'Content-Type': 'image/svg+xml'}


def get_user_profile_picture_url(user):
    """Get profile picture URL for a user, handling BLOBs and paths."""
    if not user:
        return None

    try:
        if getattr(user, 'profile_picture_blob', None) or getattr(user, 'profile_picture', None):
            return url_for('profile_picture', user_id=user.id, _external=True)
        patient = Patient.query.filter_by(user_id=user.id).first()
        if patient and (getattr(patient, 'profile_picture_blob', None) or getattr(patient, 'profile_picture', None)):
            return url_for('profile_picture', user_id=user.id, _external=True)
    except Exception:
        pass

    return url_for('profile_picture', user_id=user.id, _external=True)


@app.route('/api/user/<int:user_id>/set-availability', methods=['POST'])
@login_required
@csrf.exempt
def api_set_user_availability(user_id):
    """Set a simple availability flag for the current user (used by the communication UI).
    This updates `show_availability` for doctors and will also allow patients to toggle a lightweight presence flag.
    """
    if current_user.id != user_id and current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    data = request.get_json() or {}
    avail = data.get('available')
    if avail is None:
        return jsonify({'success': False, 'error': 'available boolean required'}), 400

    try:
        # For doctors we persist show_availability; for other users we reuse same column if present
        try:
            current_user.show_availability = bool(avail)
        except Exception:
            # Fallback: try to set attribute anyway
            setattr(current_user, 'show_availability', bool(avail))

        db.session.add(current_user)
        db.session.commit()

        # Emit socket event to notify presence change (best-effort)
        try:
            if SOCKETIO_AVAILABLE:
                socketio.emit('user_availability_changed', {'user_id': current_user.id, 'available': bool(avail)})
        except Exception:
            pass

        return jsonify({'success': True, 'available': bool(avail)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

    
# Admin Communication Dashboard
@app.route('/admin/communication')
@login_required
def admin_communication():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Get all communications for admin view
    communications = db.session.query(
        Communication,
        Appointment,
        User,
        Patient,
        Doctor
    ).join(
        Appointment, Communication.appointment_id == Appointment.id
    ).join(
        User, Communication.sender_id == User.id
    ).join(
        Patient, Appointment.patient_id == Patient.id
    ).join(
        Doctor, Appointment.doctor_id == Doctor.id
    ).order_by(Communication.timestamp.desc()).all()

    # Get appointments for sidebar and compute per-appointment unread counts
    raw_appointments = db.session.query(
        Appointment
    ).join(
        Patient
    ).join(
        Doctor
    ).order_by(Appointment.appointment_date.desc()).all()

    appointments = []
    consultation_messages = {}
    consultations = []
    active_video_consultations = []
    recordings_snapshot = []
    for apt in raw_appointments:
        try:
            unread_count = Communication.query.filter_by(appointment_id=apt.id, is_read=False).count()
        except Exception:
            unread_count = 0
        appointments.append({'appointment': apt, 'unread_count': unread_count})

        payment = Payment.query.filter_by(appointment_id=apt.id).order_by(Payment.created_at.desc()).first()
        message_rows = Communication.query.filter_by(appointment_id=apt.id).order_by(Communication.timestamp.desc()).limit(20).all()
        latest_call = CallHistory.query.filter_by(appointment_id=apt.id).order_by(CallHistory.initiated_at.desc()).first()

        patient_user = apt.patient.user if getattr(apt, 'patient', None) else None
        doctor_user = apt.doctor.user if getattr(apt, 'doctor', None) else None

        consultation_messages[str(apt.id)] = _serialize_admin_message_thread(apt.id)

        consultation_record = {
            'appointment_id': apt.id,
            'patient_name': safe_display_name(patient_user) if patient_user else 'Unknown Patient',
            'doctor_name': safe_display_name(doctor_user) if doctor_user else 'Unknown Doctor',
            'reason': apt.symptoms or apt.notes or 'General consultation',
            'appointment_date': apt.appointment_date.isoformat() if apt.appointment_date else None,
            'consultation_type': apt.consultation_type or 'consultation',
            'appointment_status': apt.status or 'scheduled',
            'payment_status': payment.status if payment else 'pending',
            'amount': float(payment.amount) if payment and payment.amount is not None else float(apt.doctor.consultation_fee) if getattr(apt, 'doctor', None) and apt.doctor.consultation_fee is not None else 0,
            'currency': payment.currency if payment and payment.currency else 'KES',
            'message_count': len(consultation_messages[str(apt.id)]),
            'unread_count': unread_count,
            'latest_call': latest_call.to_dict() if latest_call else None,
            'has_active_call': bool(latest_call and latest_call.status in ('ringing', 'accepted', 'connecting', 'connected') and not latest_call.ended_at)
        }
        consultations.append(consultation_record)

        if consultation_record['has_active_call'] and consultation_record.get('consultation_type') == 'video':
            active_video_consultations.append(consultation_record)

        if latest_call:
            recordings_snapshot.append({
                'appointment_id': apt.id,
                'patient_name': consultation_record['patient_name'],
                'doctor_name': consultation_record['doctor_name'],
                'consultation_type': consultation_record['consultation_type'],
                'appointment_date': consultation_record['appointment_date'],
                'recording_url': latest_call.recording_url,
                'recording_duration': latest_call.recording_duration,
                'recording_size': latest_call.recording_size,
                'call_status': latest_call.status,
                'call_end_reason': latest_call.end_reason,
                'recorded_at': latest_call.ended_at.isoformat() if latest_call.ended_at else (latest_call.initiated_at.isoformat() if latest_call.initiated_at else None)
            })

    # Dashboard statistics derived from DB
    try:
        total_messages = Communication.query.count()
    except Exception:
        total_messages = len(communications)

    try:
        video_calls = Appointment.query.filter(Appointment.consultation_type == 'video').count()
    except Exception:
        video_calls = 0

    try:
        voice_calls = Appointment.query.filter(Appointment.consultation_type == 'voice').count()
    except Exception:
        voice_calls = 0

    try:
        documents_shared = Communication.query.filter(Communication.message_type == 'document').count() + MedicalRecord.query.count()
    except Exception:
        documents_shared = 0

    try:
        active_calls = CallHistory.query.filter(CallHistory.status.in_(['ringing', 'accepted', 'connecting', 'connected'])).count()
    except Exception:
        active_calls = 0

    try:
        ringing_calls = CallHistory.query.filter(CallHistory.status == 'ringing').count()
    except Exception:
        ringing_calls = 0

    lives_summary = _derive_consultation_lives_summary(consultations)

    partners_payload = []
    try:
        partners_payload = [partner.to_dict() for partner in Partner.query.filter_by(is_active=True).order_by(Partner.partner_type.asc(), Partner.name.asc()).limit(100).all()]
    except Exception:
        partners_payload = []

    region_stats = {'regions': [], 'total_patients': 0, 'with_location': 0, 'without_location': 0}
    try:
        patient_rows = db.session.query(Patient, User).join(User, Patient.user_id == User.id).all()
        counts = {}
        with_location = 0
        for patient_row, user_row in patient_rows:
            region_label = (patient_row.city or patient_row.country or '').strip()
            if not region_label:
                region_label = (patient_row.address or '').strip()
            if not region_label and getattr(user_row, 'last_known_timezone', None):
                region_label = user_row.last_known_timezone
            if not region_label:
                region_label = 'Unknown'
            counts[region_label] = counts.get(region_label, 0) + 1
            if region_label != 'Unknown':
                with_location += 1
        region_stats = {
            'regions': [{'region': region, 'count': count} for region, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)],
            'total_patients': len(patient_rows),
            'with_location': with_location,
            'without_location': max(0, len(patient_rows) - with_location),
        }
    except Exception:
        pass

    consultation_settings = _get_consultation_settings()

    return render_template('admin/communication.html',
                         communications=communications,
                         consultations=consultations,
                         consultation_messages=consultation_messages,
                         lives_summary=lives_summary,
                         active_video_consultations=active_video_consultations,
                         recordings_snapshot=recordings_snapshot,
                         partners=partners_payload,
                         region_stats=region_stats,
                         appointments=appointments,
                         consultation_settings=consultation_settings,
                         stats={
                             'total_messages': total_messages,
                             'video_calls': video_calls,
                             'voice_calls': voice_calls,
                             'documents_shared': documents_shared,
                             'active_calls': active_calls,
                             'ringing_calls': ringing_calls
                         },
                         iceServers=app.config.get('ICE_SERVERS', []))


@app.route('/admin/consultation-settings', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def admin_consultation_settings():
    """GET/POST consultation room timing settings."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    if request.method == 'GET':
        settings = _get_consultation_settings()
        return jsonify(settings)

    data = request.get_json(silent=True) or {}
    allowed_keys = {'open_before_minutes', 'open_after_minutes'}
    for key in allowed_keys:
        if key in data:
            try:
                value = int(data[key])
            except (ValueError, TypeError):
                value = 0
            row = SiteContent.query.filter_by(section='consultation_settings', key=key).first()
            if row:
                row.value = str(value)
            else:
                row = SiteContent(section='consultation_settings', key=key, value=str(value), content_type='text')
                db.session.add(row)
    db.session.commit()
    return jsonify({'success': True, 'settings': _get_consultation_settings()})


# ═══════════════════════════════════════════════════════════════
#  ADMIN COMMUNICATION MONITORING APIs
# ═══════════════════════════════════════════════════════════════

@app.route('/admin/api/doctors')
@login_required
def admin_api_doctors():
    """List all doctors with their appointment counts for message monitoring."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    doctors = db.session.query(Doctor, User).join(User, Doctor.user_id == User.id).all()
    result = []
    for doc, usr in doctors:
        apt_count = Appointment.query.filter_by(doctor_id=doc.id).count()
        result.append({
            'doctor_id': doc.id,
            'user_id': usr.id,
            'name': f'{usr.first_name} {usr.last_name}',
            'specialization': getattr(doc, 'specialization', ''),
            'appointment_count': apt_count,
        })
    return jsonify({'success': True, 'doctors': result})


@app.route('/admin/api/doctor/<int:doctor_id>/appointments')
@login_required
def admin_api_doctor_appointments(doctor_id):
    """List appointments for a specific doctor with patient info."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    appointments = Appointment.query.filter_by(doctor_id=doctor_id).order_by(Appointment.appointment_date.desc()).limit(100).all()
    result = []
    for apt in appointments:
        patient = apt.patient
        patient_user = patient.user if patient else None
        result.append({
            'id': apt.id,
            'patient_name': f'{patient_user.first_name} {patient_user.last_name}' if patient_user else 'Unknown',
            'appointment_date': apt.appointment_date.isoformat() if apt.appointment_date else None,
            'status': apt.status,
            'consultation_type': getattr(apt, 'consultation_type', ''),
        })
    return jsonify({'success': True, 'appointments': result})
@app.route('/admin/api/live-rooms')
@login_required
def admin_api_live_rooms():
    """Get all active consultation rooms with participants."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    active_rooms = ConsultationRoom.query.filter(ConsultationRoom.status.in_(['waiting', 'active'])).all()
    result = []
    for room in active_rooms:
        appointment = db.session.get(Appointment, room.appointment_id)
        if not appointment:
            continue
        doctor = db.session.get(Doctor, appointment.doctor_id)
        doctor_user = doctor.user if doctor else None
        patient = appointment.patient
        patient_user = patient.user if patient else None

        room_key = f'consultation:{room.room_token}'
        participants = list(room_memberships.get(room_key, {}).values())

        result.append({
            'room_id': room.id,
            'appointment_id': room.appointment_id,
            'status': room.status,
            'doctor_name': f'{doctor_user.first_name} {doctor_user.last_name}' if doctor_user else 'Unknown',
            'patient_name': f'{patient_user.first_name} {patient_user.last_name}' if patient_user else 'Unknown',
            'started_at': room.started_at.isoformat() if room.started_at else None,
            'participant_count': len(participants),
            'participants': participants,
            'is_open': room.is_open,
        })
    return jsonify({'success': True, 'rooms': result})


@app.route('/admin/api/consultation-history')
@login_required
def admin_api_consultation_history():
    """Get completed consultation rooms with full details."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    rooms = ConsultationRoom.query.filter_by(status='ended').order_by(ConsultationRoom.ended_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    result = []
    for room in rooms.items:
        appointment = db.session.get(Appointment, room.appointment_id)
        if not appointment:
            continue
        doctor = db.session.get(Doctor, appointment.doctor_id)
        doctor_user = doctor.user if doctor else None
        patient = appointment.patient
        patient_user = patient.user if patient else None

        # Calculate duration
        duration = 0
        if room.started_at and room.ended_at:
            duration = int((room.ended_at - room.started_at).total_seconds())

        # Get review/testimonial
        testimonial = Testimonial.query.filter_by(appointment_id=room.appointment_id).first()

        # Get recording
        recording = ConsultationRecording.query.filter_by(consultation_room_id=room.id).first()

        result.append({
            'room_id': room.id,
            'appointment_id': room.appointment_id,
            'doctor_name': f'{doctor_user.first_name} {doctor_user.last_name}' if doctor_user else 'Unknown',
            'patient_name': f'{patient_user.first_name} {patient_user.last_name}' if patient_user else 'Unknown',
            'appointment_booked_at': appointment.created_at.isoformat() if getattr(appointment, 'created_at', None) else None,
            'started_at': room.started_at.isoformat() if room.started_at else None,
            'ended_at': room.ended_at.isoformat() if room.ended_at else None,
            'duration_seconds': duration,
            'review_rating': testimonial.rating if testimonial else None,
            'review_content': testimonial.content if testimonial else None,
            'has_recording': recording is not None,
            'recording_id': recording.id if recording else None,
            'session_notes': room.session_notes,
        })
    return jsonify({'success': True, 'history': result, 'total': rooms.total, 'pages': rooms.pages, 'page': page})


@app.route('/admin/api/recording/<int:recording_id>/download')
@login_required
def admin_api_download_recording(recording_id):
    """Download a consultation recording (admin only)."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    recording = db.session.get(ConsultationRecording, recording_id)
    if not recording or not recording.recording_filename:
        return jsonify({'error': 'Recording not found'}), 404
    filepath = os.path.join(app.root_path, 'uploads', 'recordings', recording.recording_filename)
    if not os.path.isfile(filepath):
        return jsonify({'error': 'Recording file not found'}), 404
    return send_file(filepath, as_attachment=True, download_name=recording.recording_filename)


@app.route('/api/consultation-room/<int:appointment_id>/upload-recording', methods=['POST'])
@login_required
@csrf.exempt
def upload_consultation_recording(appointment_id):
    """Upload a recorded consultation from the client-side MediaRecorder."""
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        return jsonify({'error': 'not_found'}), 404

    room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
    if not room:
        return jsonify({'error': 'room_not_found'}), 404

    file = request.files.get('recording')
    if not file:
        return jsonify({'error': 'no_file'}), 400

    # Ensure uploads/recordings directory exists
    rec_dir = os.path.join(app.root_path, 'uploads', 'recordings')
    os.makedirs(rec_dir, exist_ok=True)

    # Generate safe filename
    import uuid as _uuid
    ext = 'webm'
    filename = f'consultation_{appointment_id}_{room.id}_{_uuid.uuid4().hex[:8]}.{ext}'
    filepath = os.path.join(rec_dir, filename)
    file.save(filepath)
    file_size = os.path.getsize(filepath)

    doctor = db.session.get(Doctor, appointment.doctor_id)
    doctor_user = doctor.user if doctor else None
    patient = appointment.patient
    patient_user = patient.user if patient else None

    # Calculate duration
    duration = 0
    if room.started_at and room.ended_at:
        duration = int((room.ended_at - room.started_at).total_seconds())

    # Get testimonial if exists
    testimonial = Testimonial.query.filter_by(appointment_id=appointment_id).first()

    rec = ConsultationRecording(
        consultation_room_id=room.id,
        appointment_id=appointment_id,
        doctor_id=appointment.doctor_id,
        patient_id=appointment.patient_id,
        doctor_name=f'{doctor_user.first_name} {doctor_user.last_name}' if doctor_user else 'Unknown',
        patient_name=f'{patient_user.first_name} {patient_user.last_name}' if patient_user else 'Unknown',
        appointment_booked_at=getattr(appointment, 'created_at', None),
        started_at=room.started_at,
        ended_at=room.ended_at,
        duration_seconds=duration,
        recording_filename=filename,
        recording_size=file_size,
        recording_type=request.form.get('type', 'video'),
        review_rating=testimonial.rating if testimonial else None,
        review_content=testimonial.content if testimonial else None,
        status='completed',
    )
    db.session.add(rec)
    db.session.commit()

    return jsonify({'success': True, 'recording_id': rec.id})


# ═══════════════════════════════════════════════════════════════
#  ADMIN SITE EDITOR ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/admin/site-editor')
@login_required
def admin_site_editor():
    """Admin CMS page — edit all public website content."""
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    content = _get_site_content_dict()
    return render_template('admin/site_editor.html', content=content)


@app.route('/admin/site-editor/save', methods=['POST'])
@login_required
@csrf.exempt
def admin_site_editor_save():
    """Save site content changes from the editor."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    import json as _json
    data = request.get_json(silent=True) or {}
    items = data.get('items', [])
    if not items:
        return jsonify({'error': 'No items to save'}), 400

    saved = 0
    for item in items:
        section = item.get('section', '').strip()
        key = item.get('key', '').strip()
        value = item.get('value', '')
        if not section or not key:
            continue
        row = SiteContent.query.filter_by(section=section, key=key).first()
        if row:
            row.value = value
            row.updated_by = current_user.id
            saved += 1
        else:
            ctype = item.get('content_type', 'text')
            row = SiteContent(section=section, key=key, value=value,
                              content_type=ctype, updated_by=current_user.id)
            db.session.add(row)
            saved += 1
    db.session.commit()
    return jsonify({'ok': True, 'saved': saved})


@app.route('/admin/site-editor/upload', methods=['POST'])
@login_required
def admin_site_editor_upload():
    """Handle image uploads from the site editor."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    section = request.form.get('section', '').strip()
    key = request.form.get('key', '').strip()
    file = request.files.get('file')
    if not file or not file.filename or not section or not key:
        return jsonify({'error': 'Missing file, section or key'}), 400

    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        return jsonify({'error': 'Invalid file type'}), 400

    # Save to static/uploads/site/ directory
    upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'site')
    os.makedirs(upload_dir, exist_ok=True)
    stored_name = f"{uuid4().hex}__{filename}"
    dest = os.path.join(upload_dir, stored_name)
    file.save(dest)

    rel_path = f"uploads/site/{stored_name}"

    # Save the path in SiteContent
    row = SiteContent.query.filter_by(section=section, key=key).first()
    if row:
        row.value = rel_path
        row.updated_by = current_user.id
    else:
        row = SiteContent(section=section, key=key, value=rel_path,
                          content_type='image', updated_by=current_user.id)
        db.session.add(row)
    db.session.commit()

    return jsonify({'ok': True, 'url': url_for('static', filename=rel_path)})


@app.route('/admin/site-editor/reset', methods=['POST'])
@login_required
@csrf.exempt
def admin_site_editor_reset():
    """Reset site content to factory defaults by re-running the seed script."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    try:
        # Clear all existing content
        SiteContent.query.delete()
        db.session.commit()
        # Re-seed defaults
        from scripts.add_site_content_migration import DEFAULTS
        for section, key, value, ctype in DEFAULTS:
            entry = SiteContent(section=section, key=key, value=value, content_type=ctype)
            db.session.add(entry)
        db.session.commit()
        return jsonify({'ok': True, 'message': 'All content reset to defaults'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


from models import Report

@app.route('/doctor/reports', methods=['GET'])
@login_required
def get_doctor_reports():
    if current_user.role != 'doctor':
        return jsonify({'error': 'Unauthorized'}), 403
    reports = Report.query.filter_by(doctor_id=current_user.doctor_profile.id).order_by(Report.created_at.desc()).all()
    data = [
        {
            'id': r.id,
            'title': r.title,
            'description': r.description,
            'created_at': r.created_at.strftime('%Y-%m-%d %H:%M') if r.created_at else ''
        }
        for r in reports
    ]
    return jsonify(data)

@app.route('/doctor/emergency_call', methods=['POST'])
@login_required
def doctor_emergency_call():
    if current_user.role != 'doctor':
        return jsonify({'error': 'Unauthorized'}), 403
    # Here you can implement logic to notify admins, send SMS, or log the emergency event
    # For now, just log the call and return success
    from datetime import datetime
    # Example: log to AuditLog
    log = AuditLog(
        user_id=current_user.id,
        action='emergency_call',
        description=f'Doctor {current_user.get_display_name()} triggered an emergency call.',
        timestamp=now_eat()
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Emergency call logged and admins notified.'})

# Doctor Communication Dashboard
@app.route('/doctor/communication')
@login_required
def doctor_communication():
    if current_user.role != 'doctor':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()

    appointments = Appointment.query.filter(
        Appointment.doctor_id == doctor.id
    ).order_by(Appointment.appointment_date.desc()).all()

    if appointments:
        return redirect(url_for('communication_dashboard', appointment_id=appointments[0].id))

    return render_template('communication/communication_dashboard_new.html',
                         appointment=None,
                         appointments=[],
                         messages=[],
                         prescriptions=[],
                         payment_required=False,
                         payment_url=None)

# Patient Communication Dashboard
@app.route('/patient/communication')
@login_required
def patient_communication():
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()

    appointments = Appointment.query.filter(
        Appointment.patient_id == patient.id
    ).order_by(Appointment.appointment_date.desc()).all()

    if appointments:
        return redirect(url_for('communication_dashboard', appointment_id=appointments[0].id))

    return render_template('communication/communication_dashboard_new.html',
                         appointment=None,
                         appointments=[],
                         messages=[],
                         prescriptions=[],
                         payment_required=False,
                         payment_url=None)

# Universal communication handler for specific appointment
@app.route('/communication/appointment/<int:appointment_id>')
@login_required
def communication_appointment(appointment_id):
    return redirect(url_for('communication_dashboard', appointment_id=appointment_id))


# ==========================
# Testimonials
# ==========================
@app.route('/api/testimonial', methods=['POST'])
@login_required
@csrf.exempt
def submit_testimonial_api():
    """Submit a testimonial at the end of a consultation (patient only)."""
    if current_user.role != 'patient':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    data = request.get_json() or request.form
    appointment_id = data.get('appointment_id')
    rating = data.get('rating')
    content = data.get('content', '').strip()

    if not appointment_id or rating is None:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    try:
        rating = int(rating)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid rating'}), 400

    if rating < 1 or rating > 5:
        return jsonify({'success': False, 'error': 'Rating must be between 1 and 5'}), 400

    appointment = Appointment.query.get_or_404(appointment_id)
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient or appointment.patient_id != patient.id:
        return jsonify({'success': False, 'error': 'Access denied for this appointment'}), 403

    # Create testimonial
    testimonial = Testimonial(
        patient_id=patient.id,
        doctor_id=appointment.doctor_id,
        appointment_id=appointment.id,
        rating=rating,
    )
    testimonial.content = content

    db.session.add(testimonial)
    db.session.commit()

    # Return new average rating for the doctor
    doctor = db.session.get(Doctor, testimonial.doctor_id)
    avg = doctor.average_rating if doctor else None

    return jsonify({'success': True, 'testimonial_id': testimonial.id, 'doctor_average': avg}), 201


@app.route('/api/appointments/<int:appointment_id>/testimonial', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def submit_testimonial_for_appointment(appointment_id):
    """GET: check existing testimonial. POST: submit a new testimonial."""
    if current_user.role != 'patient':
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    appointment = Appointment.query.get_or_404(appointment_id)
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient or appointment.patient_id != patient.id:
        return jsonify({'success': False, 'error': 'Access denied for this appointment'}), 403

    if request.method == 'GET':
        existing = Testimonial.query.filter_by(appointment_id=appointment_id, patient_id=patient.id).first()
        if existing:
            return jsonify({'exists': True, 'testimonial_id': existing.id, 'rating': existing.rating, 'content': existing.content})
        return jsonify({'exists': False})

    data = request.get_json() or request.form
    rating = data.get('rating')
    content = data.get('content', '').strip()
    is_public = data.get('is_public', True)

    if rating is None:
        return jsonify({'success': False, 'error': 'Missing rating'}), 400

    try:
        rating = int(rating)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid rating'}), 400

    if rating < 1 or rating > 5:
        return jsonify({'success': False, 'error': 'Rating must be between 1 and 5'}), 400

    # Create testimonial
    testimonial = Testimonial(
        patient_id=patient.id,
        doctor_id=appointment.doctor_id,
        appointment_id=appointment.id,
        rating=rating,
        is_public=bool(is_public),
    )
    testimonial.content = content

    db.session.add(testimonial)
    # Store rating on appointment too
    try:
        appointment.rating = rating
        appointment.feedback = content
    except Exception:
        pass
    db.session.commit()

    doctor = db.session.get(Doctor, testimonial.doctor_id)
    avg = doctor.average_rating if doctor else None

    return jsonify({'success': True, 'testimonial_id': testimonial.id, 'doctor_average': avg}), 201


@app.route('/appointments/<int:appointment_id>/testimonial', methods=['GET'])
@login_required
def show_testimonial_form(appointment_id):
    """Render a simple testimonial submission page for patients after a call."""
    if current_user.role != 'patient':
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    appointment = Appointment.query.get_or_404(appointment_id)
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient or appointment.patient_id != patient.id:
        flash('Access denied for this appointment', 'error')
        return redirect(url_for('patient_dashboard'))

    doctor = db.session.get(Doctor, appointment.doctor_id)
    return render_template('patient/submit_testimonial.html', appointment=appointment, doctor=doctor)


# Dedicated testimonials listing (system-wide and per-doctor)
@app.route('/testimonials')
def testimonials_page():
    # Prepare doctors list for client-side filter (public subset)
    doctors = []
    try:
        docs = db.session.query(Doctor, User).join(User, Doctor.user_id == User.id).all()
        for d, u in docs:
            doctors.append({'id': d.id, 'name': u.get_display_name()})
    except Exception:
        doctors = []

    selected = request.args.get('doctor_id')
    return render_template('testimonials.html', doctors=doctors, selected_doctor=selected)


@app.route('/doctors/<int:doctor_id>/testimonials')
def doctor_testimonials_page(doctor_id):
    # Reuse the testimonials page but pre-select the doctor
    doctors = []
    try:
        docs = db.session.query(Doctor, User).join(User, Doctor.user_id == User.id).all()
        for d, u in docs:
            doctors.append({'id': d.id, 'name': u.get_display_name()})
    except Exception:
        doctors = []

    return render_template('testimonials.html', doctors=doctors, selected_doctor=str(doctor_id))


@app.route('/api/testimonials')
def get_testimonials():
    """Return recent public testimonials for display with profile pictures."""
    # Pagination and sorting
    try:
        page = int(request.args.get('page', 1))
    except Exception:
        page = 1
    try:
        per_page = int(request.args.get('per_page', 10))
    except Exception:
        per_page = 10

    sort_by = request.args.get('sort_by', 'created_at')  # or 'rating'
    doctor_filter = request.args.get('doctor_id')

    if not _table_exists('testimonials'):
        return jsonify({'testimonials': [], 'total': 0, 'page': page, 'per_page': per_page, 'doctor_average': None})

    try:
        q = Testimonial.query.filter_by(is_public=True)
        if doctor_filter:
            try:
                q = q.filter(Testimonial.doctor_id == int(doctor_filter))
            except Exception:
                pass

        # Sorting
        if sort_by == 'rating':
            q = q.order_by(Testimonial.rating.desc(), Testimonial.created_at.desc())
        else:
            q = q.order_by(Testimonial.created_at.desc())

        total = q.count()
        items = q.offset((page - 1) * per_page).limit(per_page).all()
    except Exception:
        return jsonify({'testimonials': [], 'total': 0, 'page': page, 'per_page': per_page, 'doctor_average': None})

    out = []
    for t in items:
        try:
            patient_name = t.patient.user.get_display_name() if t.patient and t.patient.user else None
            patient_id = t.patient.user.id if t.patient and t.patient.user else None
        except Exception:
            patient_name = None
            patient_id = None
        try:
            doctor_user = t.doctor.user if t.doctor and getattr(t.doctor, 'user', None) else None
            doctor_name = doctor_user.get_display_name() if doctor_user else None
            doctor_id = doctor_user.id if doctor_user else None
        except Exception:
            doctor_name = None
            doctor_id = None

        out.append({
            'id': t.id,
            'patient_name': patient_name,
            'patient_id': patient_id,
            'doctor_name': doctor_name,
            'doctor_id': t.doctor_id,
            'rating': t.rating,
            'content': t.content,
            'created_at': t.created_at.isoformat()
        })

    # Compute doctor average if filtered
    doctor_avg = None
    if doctor_filter:
        try:
            doctor_avg = db.session.query(func.avg(Testimonial.rating)).filter(Testimonial.doctor_id == int(doctor_filter), Testimonial.is_public == True).scalar()
            if doctor_avg is not None:
                doctor_avg = round(float(doctor_avg), 2)
        except Exception:
            doctor_avg = None

    return jsonify({
        'testimonials': out,
        'total': total,
        'page': page,
        'per_page': per_page,
        'doctor_average': doctor_avg
    })


@app.route('/api/doctors/<int:doctor_id>/profile-with-reviews')
def get_doctor_profile_with_reviews(doctor_id):
    """Get doctor profile with testimonials and average rating (public)."""
    try:
        doctor = db.session.get(Doctor, doctor_id)
        if not doctor:
            return jsonify({'error': 'Doctor not found'}), 404
        
        user = doctor.user
        
        testimonials = []
        avg_rating = 0
        if _table_exists('testimonials'):
            testimonials = Testimonial.query.filter_by(doctor_id=doctor_id, is_public=True).order_by(
                Testimonial.created_at.desc()
            ).limit(10).all()

            avg_value = db.session.query(func.avg(Testimonial.rating)).filter(
                Testimonial.doctor_id == doctor_id,
                Testimonial.is_public == True
            ).scalar()
            avg_rating = round(float(avg_value), 2) if avg_value else 0
        
        # Build testimonials list
        testimonials_list = []
        for t in testimonials:
            try:
                patient_name = t.patient.user.get_display_name() if t.patient and t.patient.user else "Anonymous"
                patient_id = t.patient.user.id if t.patient and t.patient.user else None
            except:
                patient_name = "Anonymous"
                patient_id = None
            
            testimonials_list.append({
                'id': t.id,
                'patient_name': patient_name,
                'patient_id': patient_id,
                'rating': t.rating,
                'content': t.content,
                'created_at': t.created_at.isoformat()
            })
        
        return jsonify({
            'doctor': {
                'id': doctor.id,
                'name': user.get_display_name() if user else "Unknown",
                'specialization': doctor.specialization,
                'bio': getattr(doctor, 'bio', None),
                'experience_years': doctor.experience_years,
                'qualifications': doctor.qualifications,
                'average_rating': avg_rating,
                'testimonials_count': len(testimonials),
                'testimonials': testimonials_list
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def verify_appointment_access(appointment, user):
    if user.role == 'admin':
        return True
    elif user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=user.id).first()
        return appointment.doctor_id == doctor.id
    elif user.role == 'patient':
        patient = Patient.query.filter_by(user_id=user.id).first()
        return appointment.patient_id == patient.id
    return False

# Helper function to check if consultation payment is complete
def is_consultation_paid(appointment_id):
    """Check if consultation fee has been paid for an appointment"""
    try:
        payment = Payment.query.filter_by(
            appointment_id=appointment_id,
            status='paid'
        ).first()
        return payment is not None
    except Exception:
        return False
def get_appointment_payment_status(appointment_id):
    """Get detailed payment status for an appointment"""
    try:
        payment = Payment.query.filter_by(appointment_id=appointment_id).first()
        if not payment:
            return {'status': 'no_payment', 'paid': False}
        
        return {
            'status': payment.status,
            'paid': payment.status == 'paid',
            'amount': payment.amount,
            'currency': payment.currency,
            'payment_id': payment.id,
            'created_at': payment.created_at.isoformat() if payment.created_at else None
        }
    except Exception as e:
        print(f"Error getting payment status: {e}")
        return {'status': 'error', 'paid': False}
def _stream_communication_file(comm):
    """Decrypt and stream a communication file object."""
    stored_path = comm.file_path
    full_path = resolve_stored_path(stored_path)
    if not full_path or not os.path.exists(full_path):
        return abort(404)

    # Parse original filename from storage name (uuid__orig.ext.enc)
    base = os.path.basename(stored_path)
    orig_name = base
    if '__' in base:
        orig_part = base.split('__', 1)[1]
        if orig_part.endswith('.enc'):
            orig_name = orig_part[:-4]

    try:
        with open(full_path, 'rb') as fh:
            encrypted_bytes = fh.read()
        decrypted = decrypt_file_bytes(encrypted_bytes)
    except Exception:
        return abort(500)

    bio = BytesIO(decrypted)
    bio.seek(0)
    try:
        return send_file(bio, as_attachment=True, download_name=orig_name, mimetype='application/octet-stream')
    except TypeError:
        return send_file(bio, as_attachment=True, attachment_filename=orig_name, mimetype='application/octet-stream')


def _signed_comm_download_url_for_user(communication_id, user_id, expires_in=300):
    """Build a short-lived signed download URL for a communication file."""
    expires_in = max(30, min(int(expires_in or 300), 3600))
    payload = {
        'communication_id': int(communication_id),
        'user_id': int(user_id),
        'exp': int(time.time()) + int(expires_in)
    }
    token = s.dumps(payload, salt='communication-download')
    return url_for('download_communication_file_signed', token=token, _external=True)


@app.route('/api/communication/<int:communication_id>/signed-url', methods=['GET'])
@login_required
def get_signed_communication_url(communication_id):
    """Create short-lived signed URL for communication file download/preview."""
    try:
        comm = db.session.get(Communication, communication_id)
        if not comm or not comm.file_path:
            return jsonify({'success': False, 'error': 'file_not_found'}), 404

        appointment = db.session.get(Appointment, comm.appointment_id)
        if not appointment or not verify_appointment_access(appointment, current_user):
            return jsonify({'success': False, 'error': 'access_denied'}), 403

        expires_in = request.args.get('expires_in', 300, type=int)
        expires_in = max(30, min(expires_in, 3600))
        signed_url = _signed_comm_download_url_for_user(communication_id, current_user.id, expires_in=expires_in)

        return jsonify({'success': True, 'url': signed_url, 'expires_in': expires_in})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/download/communication/signed/<token>', methods=['GET'])
@login_required
def download_communication_file_signed(token):
    """Download communication file via signed short-lived token."""
    try:
        data = s.loads(token, salt='communication-download', max_age=3600)
        communication_id = int(data.get('communication_id'))
        token_user_id = int(data.get('user_id'))
        token_exp = int(data.get('exp'))
    except Exception:
        return abort(403)

    if int(time.time()) > token_exp:
        return abort(403)
    if int(current_user.id) != token_user_id:
        return abort(403)

    comm = db.session.get(Communication, communication_id)
    if not comm:
        return abort(404)

    appointment = db.session.get(Appointment, comm.appointment_id)
    if not appointment or not verify_appointment_access(appointment, current_user):
        return abort(403)

    return _stream_communication_file(comm)


# Endpoint to download communication file (decrypt and stream)
@app.route('/download/communication/<int:communication_id>')
@login_required
def download_communication_file(communication_id):
    comm = Communication.query.get_or_404(communication_id)
    appointment = db.session.get(Appointment, comm.appointment_id)
    if not verify_appointment_access(appointment, current_user):
        return abort(403)
    return _stream_communication_file(comm)


# Endpoint to download medical record file (decrypt and stream)
@app.route('/download/medical_record/<int:record_id>')
@login_required
def download_medical_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    # Only allow patient or doctor who owns/created or admin
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if record.patient_id != patient.id:
            return abort(403)
    elif current_user.role == 'doctor':
        # Allow if doctor created the record or if the doctor is the patient's doctor
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        patient = db.session.get(Patient, record.patient_id)
        allowed = False
        if record.created_by == current_user.id:
            allowed = True
        # If doctor is assigned to this patient via any appointment, allow access
        if doctor and Appointment.query.filter_by(doctor_id=doctor.id, patient_id=patient.id).count() > 0:
            allowed = True
        if not allowed:
            return abort(403)
    elif current_user.role != 'admin':
        return abort(403)

    stored_path = record.file_path
    full_path = resolve_stored_path(stored_path)
    if not full_path or not os.path.exists(full_path):
        return abort(404)

    base = os.path.basename(stored_path)
    orig_name = base
    if '__' in base:
        orig_part = base.split('__', 1)[1]
        if orig_part.endswith('.enc'):
            orig_name = orig_part[:-4]

    try:
        with open(full_path, 'rb') as fh:
            encrypted_bytes = fh.read()
        decrypted = decrypt_file_bytes(encrypted_bytes)
    except Exception:
        return abort(500)

    bio = BytesIO(decrypted)
    bio.seek(0)
    try:
        return send_file(bio, as_attachment=True, download_name=orig_name, mimetype='application/octet-stream')
    except TypeError:
        return send_file(bio, as_attachment=True, attachment_filename=orig_name, mimetype='application/octet-stream')


def _batched_appointment_comm_meta(appointment_ids, viewer_user_id):
    """Fetch last message, unread count and latest payment status in batched queries."""
    if not appointment_ids:
        return {}, {}, {}

    # Last message per appointment (latest by timestamp, then id)
    last_message_map = {}
    last_messages = Communication.query.filter(
        Communication.appointment_id.in_(appointment_ids)
    ).order_by(Communication.appointment_id.asc(), Communication.timestamp.desc(), Communication.id.desc()).all()
    for message in last_messages:
        if message.appointment_id not in last_message_map:
            last_message_map[message.appointment_id] = message

    # Unread counts per appointment for current viewer
    unread_rows = db.session.query(
        Communication.appointment_id,
        func.count(Communication.id)
    ).filter(
        Communication.appointment_id.in_(appointment_ids),
        Communication.is_read == False,
        Communication.sender_id != viewer_user_id
    ).group_by(Communication.appointment_id).all()
    unread_count_map = {row[0]: int(row[1]) for row in unread_rows}

    # Latest payment status per appointment
    latest_payment_map = {}
    payments = Payment.query.filter(
        Payment.appointment_id.in_(appointment_ids)
    ).order_by(Payment.appointment_id.asc(), Payment.created_at.desc(), Payment.id.desc()).all()
    for payment in payments:
        if payment.appointment_id not in latest_payment_map:
            latest_payment_map[payment.appointment_id] = payment.status

    return last_message_map, unread_count_map, latest_payment_map


@app.route('/api/doctor/appointments')
@login_required
def get_doctor_appointments():
    """Get doctor's appointments grouped by patient with categorization: today, upcoming, completed, rescheduled, pending"""
    if current_user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404
    
    # Get appointments with patient info and payment status
    appointments = db.session.query(
        Appointment,
        Patient,
        User,
        Payment
    ).join(
        Patient, Appointment.patient_id == Patient.id
    ).join(
        User, Patient.user_id == User.id
    ).outerjoin(
        Payment, Appointment.id == Payment.appointment_id
    ).filter(
        Appointment.doctor_id == doctor.id
    ).order_by(Patient.id, Appointment.appointment_date.desc()).all()
    
    appointment_ids = [appointment.id for appointment, _, _, _ in appointments]
    last_message_map, unread_count_map, latest_payment_map = _batched_appointment_comm_meta(appointment_ids, current_user.id)

    # Group appointments by patient and categorize
    patients_appointments = {}  # {patient_id: {'patient_info': ..., 'today': [...], 'upcoming': [...], etc}}
    
    now = now_eat()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    for appointment, patient, user, payment in appointments:
        patient_id = patient.id
        projected_user = build_user_profile_projection(user, viewer=current_user, include_sensitive=True)
        
        # Initialize patient group if not exists
        if patient_id not in patients_appointments:
            patients_appointments[patient_id] = {
                'patient': {
                    'id': patient.id,
                    'first_name': projected_user.get('first_name'),
                    'last_name': projected_user.get('last_name'),
                    'email': projected_user.get('email'),
                    'phone': projected_user.get('phone'),
                    'profile_picture_url': url_for('profile_picture', user_id=user.id, _external=True) if user else None
                },
                'today': [],
                'upcoming': [],
                'completed': [],
                'rescheduled': [],
                'pending': []
            }
        
        last_message = last_message_map.get(appointment.id)
        
        # Determine payment status
        payment_status = 'pending'
        if latest_payment_map.get(appointment.id):
            payment_status = latest_payment_map.get(appointment.id)
        elif payment:
            payment_status = payment.status
        elif appointment.status == 'completed':
            payment_status = 'completed'
        
        appointment_data = {
            'appointment_id': appointment.id,
            'appointment_date': appointment.appointment_date.isoformat(),
            'appointment_date_formatted': appointment.appointment_date.strftime('%d %b %Y'),
            'appointment_time': appointment.appointment_date.strftime('%H:%M'),
            'consultation_type': appointment.consultation_type,
            'status': appointment.status,
            'payment_status': payment_status,
            'last_message': last_message.content if last_message else 'No messages yet',
            'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
            'unread_count': unread_count_map.get(appointment.id, 0)
        }
        
        # Categorize appointment based on date and status
        appt_date = appointment.appointment_date
        # Ensure appointment datetime is timezone-aware for comparisons
        if appt_date is not None and appt_date.tzinfo is None:
            appt_date = appt_date.replace(tzinfo=EAT_TZ)
        
        if appointment.status == 'completed':
            patients_appointments[patient_id]['completed'].append(appointment_data)
        elif appointment.status == 'rescheduled':
            patients_appointments[patient_id]['rescheduled'].append(appointment_data)
        elif appointment.status == 'pending' or (appointment.status not in ['confirmed', 'scheduled', 'completed', 'rescheduled', 'cancelled']):
            patients_appointments[patient_id]['pending'].append(appointment_data)
        elif appointment.status in ['confirmed', 'scheduled']:
            if today_start <= appt_date < today_end:
                patients_appointments[patient_id]['today'].append(appointment_data)
            elif appt_date >= today_end:
                patients_appointments[patient_id]['upcoming'].append(appointment_data)
            else:
                # Past appointments that aren't marked completed
                patients_appointments[patient_id]['completed'].append(appointment_data)
        elif appointment.status == 'cancelled':
            # Skip cancelled appointments
            pass
    
    # Convert to list format
    appointments_by_patient = list(patients_appointments.values())
    
    return jsonify({
        'appointments_by_patient': appointments_by_patient,
        'total_patients': len(patients_appointments)
    })

@app.route('/api/patient/doctors-with-appointments')
@login_required
def get_patient_doctors_with_appointments():
    """Get doctors with appointments for patient communication page"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    try:
        # Get all appointments with doctor info
        appointments = db.session.query(
            Appointment,
            Doctor,
            User
        ).join(
            Doctor, Appointment.doctor_id == Doctor.id
        ).join(
            User, Doctor.user_id == User.id
        ).filter(
            Appointment.patient_id == patient.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Group by doctor and get latest info
        doctors_map = {}
        for appointment, doctor, user in appointments:
            if doctor.id not in doctors_map:
                # Get last message for this doctor-patient
                last_message = Communication.query.filter_by(
                    appointment_id=appointment.id
                ).order_by(Communication.timestamp.desc()).first()
                
                # Get unread count
                unread_count = Communication.query.join(
                    Appointment, Communication.appointment_id == Appointment.id
                ).filter(
                    Appointment.patient_id == patient.id,
                    Appointment.doctor_id == doctor.id,
                    Communication.is_read == False,
                    Communication.sender_id != current_user.id
                ).count()
                
                # Get payment status
                payment = Payment.query.filter_by(
                    appointment_id=appointment.id
                ).order_by(Payment.created_at.desc()).first()
                
                # Check if doctor is online
                is_online = _is_user_online(user.id) if user else False
                
                doctors_map[doctor.id] = {
                    'id': doctor.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'specialization': doctor.specialization,
                    'profile_picture_url': url_for('profile_picture', user_id=user.id, _external=True) if user else None,
                    'is_online': is_online,
                    'last_message': last_message.content if last_message else None,
                    'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
                    'unread_count': unread_count,
                    'paymentStatus': payment.status if payment else 'pending'
                }
        
        return jsonify(list(doctors_map.values()))
        
    except Exception as e:
        print(f"Error in get_patient_doctors_with_appointments: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    

@app.route('/api/patient/appointments')
@login_required
def get_patient_appointments():
    """Get patient's appointments with doctor info and payment status"""
    try:
        if current_user.role != 'patient':
            return jsonify({'error': 'Access denied'}), 403
        
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        # Get appointments with doctor info and payment status - FIXED QUERY
        appointments = db.session.query(
            Appointment,
            Doctor,
            User
        ).join(
            Doctor, Appointment.doctor_id == Doctor.id
        ).join(
            User, Doctor.user_id == User.id
        ).filter(
            Appointment.patient_id == patient.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        appointment_ids = [appointment.id for appointment, _, _ in appointments]
        last_message_map, unread_count_map, latest_payment_map = _batched_appointment_comm_meta(appointment_ids, current_user.id)

        appointments_data = []
        for appointment, doctor, user in appointments:
            last_message = last_message_map.get(appointment.id)
            
            # Get payment status
            payment_status = 'pending'
            if latest_payment_map.get(appointment.id):
                payment_status = latest_payment_map.get(appointment.id)
            elif appointment.status == 'completed':
                payment_status = 'completed'
            
            # Check if doctor is online
            doctor_online = _is_user_online(user.id) if user else False
            
            appointments_data.append({
                'appointment_id': appointment.id,
                'doctor_id': doctor.id,
                'doctor': {
                    'id': doctor.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'specialization': doctor.specialization,
                    'is_online': doctor_online,
                    'profile_picture_url': url_for('profile_picture', user_id=user.id, _external=True) if user else None
                },
                'appointment_date': appointment.appointment_date.isoformat() if appointment.appointment_date else None,
                'appointment_time': appointment.appointment_date.strftime('%H:%M') if appointment.appointment_date else None,
                'consultation_type': appointment.consultation_type,
                'status': appointment.status,
                'payment_status': payment_status,
                'last_message': last_message.content if last_message else None,
                'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
                'unread_count': unread_count_map.get(appointment.id, 0)
            })
        
        return jsonify(appointments_data), 200
        
    except Exception as e:
        print(f"Error in get_patient_appointments: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    
@app.route('/api/appointment/<int:appointment_id>/payment-status')
@login_required
def get_appointment_payment_status(appointment_id):
    """Get payment status for a specific appointment"""
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Verify access
    if not verify_appointment_access(appointment, current_user):
        return jsonify({'error': 'Access denied'}), 403
    
    payment = Payment.query.filter_by(appointment_id=appointment_id).order_by(Payment.created_at.desc()).first()
    
    payment_status = 'pending'
    if payment:
        payment_status = payment.status
    elif appointment.status == 'completed':
        payment_status = 'completed'
    
    return jsonify({
        'appointment_id': appointment_id,
        'payment_status': payment_status,
        'payment_required': payment_status != 'paid' and current_user.role == 'patient'
    })



# API endpoint for doctor to get list of patients with unpaid consultations
@app.route('/api/doctor/unpaid-consultations')
@login_required
def get_doctor_unpaid_consultations():
    """Get list of patients with unpaid consultations for this doctor"""
    if current_user.role not in ['doctor', 'admin']:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        if current_user.role == 'admin':
            # Admins can see all unpaid consultations
            query = db.session.query(Appointment, Patient, User, Payment).join(
                Patient, Appointment.patient_id == Patient.id
            ).join(
                User, Patient.user_id == User.id
            ).join(
                Payment, Appointment.id == Payment.appointment_id
            ).filter(Payment.status != 'paid')
        else:
            # Doctors only see their own patients' unpaid consultations
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            query = db.session.query(Appointment, Patient, User, Payment).join(
                Patient, Appointment.patient_id == Patient.id
            ).join(
                User, Patient.user_id == User.id
            ).join(
                Payment, Appointment.id == Payment.appointment_id
            ).filter(
                Appointment.doctor_id == doctor.id,
                Payment.status != 'paid'
            )
        
        unpaid = []
        for appointment, patient, user, payment in query.all():
            unpaid.append({
                'appointment_id': appointment.id,
                'patient_name': user.first_name + ' ' + user.last_name,
                'patient_email': user.email,
                'appointment_date': appointment.appointment_date.isoformat() if appointment.appointment_date else None,
                'amount': payment.amount,
                'currency': payment.currency,
                'payment_status': payment.status,
                'consultation_type': appointment.consultation_type
            })
        
        return jsonify({'unpaid_consultations': unpaid})
    except Exception as e:
        print(f"Error fetching unpaid consultations: {e}")
        return jsonify({'error': str(e)}), 500

# API endpoint for doctor to send payment reminder to patient
@app.route('/api/appointment/<int:appointment_id>/send-payment-reminder', methods=['POST'])
@login_required
def send_payment_reminder(appointment_id):
    """Doctor sends payment reminder to patient"""
    try:
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Verify doctor access
        if current_user.role not in ['doctor', 'admin']:
            return jsonify({'error': 'Only doctors can send reminders'}), 403
        
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            if appointment.doctor_id != doctor.id:
                return jsonify({'error': 'Cannot send reminder for other doctors appointments'}), 403
        
        # Check payment status
        payment = Payment.query.filter_by(appointment_id=appointment_id).first()
        if not payment or payment.status == 'paid':
            return jsonify({'error': 'Appointment already paid'}), 400
        
        # Create system notification to patient
        patient = Patient.query.filter_by(id=appointment.patient_id).first()
        doctor_user = User.query.filter_by(id=current_user.id).first()
        
        notification_message = f"Payment Reminder: Dr. {doctor_user.first_name} {doctor_user.last_name} is reminding you to pay {payment.currency} {payment.amount} for your consultation scheduled on {appointment.appointment_date.strftime('%b %d, %Y at %I:%M %p')}. Once paid, you can start chatting, video/audio calls, and more."
        
        # Send via Communication as system message
        system_comm = Communication(
            appointment_id=appointment_id,
            sender_id=current_user.id,
            message_type='system',
            content=notification_message,
            timestamp=now_eat(),
            is_read=False,
            message_status='sent'
        )
        
        db.session.add(system_comm)
        db.session.commit()
        
        # Emit notification via Socket.IO if patient is online
        try:
            patient_user_id = patient.user_id
            if _is_user_online(patient_user_id):
                socketio.emit('payment_reminder', {
                    'message': notification_message,
                    'appointment_id': appointment_id,
                    'amount': payment.amount,
                    'currency': payment.currency,
                    'doctor_name': f"{doctor_user.first_name} {doctor_user.last_name}"
                }, room=f'user_{patient_user_id}', namespace='/')
        except Exception as e:
            print(f"Error emitting Socket.IO notification: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Payment reminder sent to patient',
            'notification_id': system_comm.id
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error sending payment reminder: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admins-list')
@login_required
def get_admins_list():
    """Get list of all admins for contact dropdown"""
    # Only allow patients and doctors to contact admins
    if not current_user_has_role('patient', 'doctor'):
        return jsonify({'error': 'Access denied'}), 403
    
    admins = User.query.filter_by(role='admin').all()
    
    admin_list = []
    for admin in admins:
        projected_admin = build_user_profile_projection(admin, viewer=current_user, include_sensitive=True)
        admin_data = {
            'id': projected_admin.get('id'),
            'first_name': projected_admin.get('first_name'),
            'last_name': projected_admin.get('last_name'),
            'email': projected_admin.get('email'),
            'profile_picture_url': get_user_profile_picture_url(admin) or '/static/images/default_avatar.png'
        }
        admin_list.append(admin_data)
    
    return jsonify({'admins': admin_list})


@app.route('/api/admin-conversation/<int:admin_id>')
@login_required
def get_admin_conversation(admin_id):
    """Get conversation messages between user and admin"""
    # Verify admin exists
    admin = User.query.get_or_404(admin_id)
    if admin.role != 'admin':
        return jsonify({'error': 'Not an admin'}), 400

    # Only allow patients and doctors
    if current_user.role not in ['patient', 'doctor']:
        return jsonify({'error': 'Access denied'}), 403

    # Get messages from the conversation between current user and admin
    # Messages are stored with admin_id as recipient_id and current user as sender
    messages = Message.query.filter(
        db.or_(
            db.and_(
                Message.sender_id == current_user.id,
                Message.recipient_id == admin_id
            ),
            db.and_(
                Message.sender_id == admin_id,
                Message.recipient_id == current_user.id
            )
        )
    ).order_by(Message.created_at.asc()).all()

    message_list = []
    for msg in messages:
        message_data = {
            'id': msg.id,
            'sender_id': msg.sender_id,
            'recipient_id': msg.recipient_id,
            'content': msg.content,
            'created_at': msg.created_at.isoformat() if msg.created_at else None,
            'is_read': msg.is_read,
            'sender_name': f"{msg.sender.first_name} {msg.sender.last_name}",
            'sender_avatar': msg.sender.profile_picture_url or '/static/images/default_avatar.png'
        }
        message_list.append(message_data)

    return jsonify({'messages': message_list})

@app.route('/api/patient/appointments/categorized')
@login_required
def get_patient_appointments_categorized():
    """Get patient's appointments grouped by doctor with categorization: today, upcoming, completed, rescheduled, pending"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    # Get all appointments for this patient with doctor info
    appointments_data = db.session.query(
        Appointment,
        Doctor,
        User,
        Payment
    ).join(
        Doctor, Appointment.doctor_id == Doctor.id
    ).join(
        User, Doctor.user_id == User.id
    ).outerjoin(
        Payment, Appointment.id == Payment.appointment_id
    ).filter(
        Appointment.patient_id == patient.id
    ).order_by(Doctor.id, Appointment.appointment_date.desc()).all()
    
    # Group appointments by doctor and categorize
    doctors_appointments = {}  # {doctor_id: {'doctor_info': ..., 'today': [...], 'upcoming': [...], etc}}
    
    now = now_eat()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    for appointment, doctor, user, payment in appointments_data:
        doctor_id = doctor.id
        
        # Initialize doctor group if not exists
        if doctor_id not in doctors_appointments:
            doctors_appointments[doctor_id] = {
                'doctor': {
                    'id': doctor.id,
                    'user': {
                        'id': user.id,
                        'first_name': user.first_name,
                        'last_name': user.last_name
                    },
                    'specialization': doctor.specialization,
                    'consultation_fee': float(doctor.consultation_fee) if doctor.consultation_fee else 0.0
                },
                'today': [],
                'upcoming': [],
                'completed': [],
                'rescheduled': [],
                'pending': []
            }
        
        # Determine payment status
        payment_status = 'pending'
        if payment:
            payment_status = payment.status
        elif appointment.status == 'completed':
            payment_status = 'completed'
        
        # Ensure we're working with proper datetime objects
        appointment_date = appointment.appointment_date
        created_at = appointment.created_at
        
        appointment_data = {
            'id': appointment.id,
            'doctor_id': doctor_id,
            'appointment_date': appointment_date.isoformat() if appointment_date else None,
            'appointment_date_formatted': appointment_date.strftime('%d %b %Y') if appointment_date else None,
            'appointment_time': appointment_date.strftime('%H:%M') if appointment_date else None,
            'consultation_type': appointment.consultation_type,
            'symptoms': appointment.symptoms,
            'notes': appointment.notes,
            'status': appointment.status,
            'payment_status': payment_status,
            'rating': appointment.rating if hasattr(appointment, 'rating') else None,
            'created_at': created_at.isoformat() if created_at else None
        }
        
        # Categorize based on status and date
        if appointment.status == 'completed':
            doctors_appointments[doctor_id]['completed'].append(appointment_data)
        elif appointment.status == 'rescheduled':
            doctors_appointments[doctor_id]['rescheduled'].append(appointment_data)
        elif appointment.status == 'pending' or (appointment.status not in ['confirmed', 'scheduled', 'completed', 'rescheduled', 'cancelled']):
            doctors_appointments[doctor_id]['pending'].append(appointment_data)
        elif appointment.status in ['confirmed', 'scheduled']:
            if today_start <= appointment_date < today_end:
                doctors_appointments[doctor_id]['today'].append(appointment_data)
            elif appointment_date >= today_end:
                doctors_appointments[doctor_id]['upcoming'].append(appointment_data)
            else:
                # Past appointments that aren't marked completed
                doctors_appointments[doctor_id]['completed'].append(appointment_data)
        elif appointment.status == 'cancelled':
            # Skip cancelled appointments
            pass
    
    # Convert to list format
    appointments_by_doctor = list(doctors_appointments.values())
    
    return jsonify({
        'appointments_by_doctor': appointments_by_doctor,
        'total_doctors': len(doctors_appointments)
    })

# Add this route to handle profile picture errors gracefully
@app.route('/api/user/<int:user_id>/basic-info')
@login_required
def get_user_basic_info(user_id):
    """Get basic user info (name only)"""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate initials
    initials = 'U'
    if user.first_name and user.last_name:
        initials = f"{user.first_name[0]}{user.last_name[0]}".upper()
    elif user.first_name:
        initials = user.first_name[0].upper()
    elif user.last_name:
        initials = user.last_name[0].upper()
    elif user.username:
        initials = user.username[0].upper()
    
    return jsonify({
        'name': user.get_display_name(),
        'initials': initials
    })

# Add fallback for patient appointments
@app.route('/api/patient/appointments/fallback')
@login_required
def get_patient_appointments_fallback():
    """Fallback endpoint for patient appointments"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify([])
    
    # Simple fallback query
    appointments = Appointment.query.filter_by(patient_id=patient.id).all()
    
    appointments_data = []
    for appointment in appointments:
        doctor = db.session.get(Doctor, appointment.doctor_id)
        if doctor:
            doctor_user = db.session.get(User, doctor.user_id)
            appointments_data.append({
                'appointment_id': appointment.id,
                'doctor': {
                    'id': doctor.id,
                    'first_name': doctor_user.first_name if doctor_user else '',
                    'last_name': doctor_user.last_name if doctor_user else '',
                    'specialization': doctor.specialization,
                    'is_online': False
                },
                'appointment_date': appointment.appointment_date.isoformat() if appointment.appointment_date else None,
                'status': appointment.status,
                'paymentStatus': 'pending'
            })
    
    return jsonify(appointments_data)


@app.route('/api/appointments', methods=['GET'])
@login_required
def get_appointments_for_messaging():
    """Canonical appointments endpoint used by messaging UIs.

    Returns normalized appointment rows with both doctor and patient info
    so older/newer templates can consume a single contract.
    """
    try:
        query = db.session.query(Appointment).order_by(Appointment.appointment_date.desc())

        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            if not doctor:
                return jsonify([]), 200
            query = query.filter(Appointment.doctor_id == doctor.id)
        elif current_user.role == 'patient':
            patient = Patient.query.filter_by(user_id=current_user.id).first()
            if not patient:
                return jsonify([]), 200
            query = query.filter(Appointment.patient_id == patient.id)
        elif current_user.role != 'admin':
            return jsonify({'error': 'Access denied'}), 403

        appointments = query.all()
        results = []

        for appointment in appointments:
            doctor = db.session.get(Doctor, appointment.doctor_id) if appointment.doctor_id else None
            doctor_user = db.session.get(User, doctor.user_id) if doctor and doctor.user_id else None

            patient = db.session.get(Patient, appointment.patient_id) if appointment.patient_id else None
            patient_user = db.session.get(User, patient.user_id) if patient and patient.user_id else None

            projected_doctor = build_user_profile_projection(doctor_user, viewer=current_user, include_sensitive=True) if doctor_user else {}
            projected_patient = build_user_profile_projection(patient_user, viewer=current_user, include_sensitive=True) if patient_user else {}

            results.append({
                'id': appointment.id,
                'appointment_id': appointment.id,
                'patient_id': appointment.patient_id,
                'doctor_id': appointment.doctor_id,
                'appointment_date': appointment.appointment_date.isoformat() if appointment.appointment_date else None,
                'status': appointment.status,
                'consultation_type': appointment.consultation_type,
                'reason': appointment.symptoms or appointment.notes or '',
                'doctor': {
                    'id': doctor.id if doctor else None,
                    'user_id': doctor_user.id if doctor_user else None,
                    'first_name': projected_doctor.get('first_name') if projected_doctor else None,
                    'last_name': projected_doctor.get('last_name') if projected_doctor else None,
                    'specialization': doctor.specialization if doctor else None,
                },
                'patient': {
                    'id': patient.id if patient else None,
                    'user_id': patient_user.id if patient_user else None,
                    'first_name': projected_patient.get('first_name') if projected_patient else None,
                    'last_name': projected_patient.get('last_name') if projected_patient else None,
                }
            })

        return jsonify(results), 200
    except Exception as e:
        app.logger.exception('Failed to fetch canonical appointments list')
        return jsonify({'error': str(e)}), 500

# API to get all available doctors for booking
@app.route('/api/doctors', methods=['GET'])
@login_required
@csrf.exempt
def get_doctors():
    """Get all available doctors for appointment booking"""
    try:
        if current_user.role != 'patient':
            return jsonify({'error': 'Access denied'}), 403
        
        doctors = db.session.query(Doctor, User).join(
            User, Doctor.user_id == User.id
        ).filter(Doctor.availability == True).all()
        
        doctors_data = []
        for doctor, user in doctors:
            projected_user = build_user_profile_projection(user, viewer=current_user, include_sensitive=True)
            doctors_data.append({
                'id': doctor.id,
                'user_id': user.id,
                'first_name': projected_user.get('first_name') or '',
                'last_name': projected_user.get('last_name') or '',
                'phone': projected_user.get('phone'),
                'specialization': doctor.specialization,
                'license_number': doctor.license_number,
                'qualifications': doctor.qualifications,
                'experience_years': doctor.experience_years,
                'consultation_fee': doctor.consultation_fee,
                'availability': doctor.availability
            })
        
        return jsonify(doctors_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API to get appointments for a patient
@app.route('/api/doctor-patients', methods=['GET'])
@login_required
def get_api_doctor_patients():
    """Get all patients for doctor as JSON API"""
    if not current_user_has_role('doctor'):
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404
    
    # Get unique patients for this doctor
    patients_data = db.session.query(
        Patient,
        User
    ).join(
        User, Patient.user_id == User.id
    ).join(
        Appointment, Appointment.patient_id == Patient.id
    ).filter(
        Appointment.doctor_id == doctor.id
    ).distinct(Patient.id).all()
    
    patient_list = []
    for patient, user in patients_data:
        projected_user = build_user_profile_projection(user, viewer=current_user, include_sensitive=True)
        patient_list.append({
            'id': patient.id,
            'user_id': user.id,
            'first_name': projected_user.get('first_name'),
            'last_name': projected_user.get('last_name'),
            'email': projected_user.get('email'),
            'phone': projected_user.get('phone')
        })
    
    return jsonify({'patients': patient_list, 'total': len(patient_list)})


@app.route('/doctor/patients', methods=['GET'])
def get_doctor_patients():
    """Render all patients for a doctor with their appointments categorized by status"""
    if not current_user_has_role('doctor'):
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    doctor = current_user.doctor_profile
    if not doctor:
        flash('Doctor profile not found', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get all appointments for this doctor with patient info
        appointments_query = db.session.query(
            Appointment,
            Patient,
            User
        ).join(
            Patient, Appointment.patient_id == Patient.id
        ).join(
            User, Patient.user_id == User.id
        ).filter(
            Appointment.doctor_id == doctor.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Categorize appointments
        upcoming_appointments = []
        completed_appointments = []
        rescheduled_appointments = []
        pending_appointments = []
        
        now = now_eat()
        
        for appointment, patient, user in appointments_query:
            projected_user = build_user_profile_projection(user, viewer=current_user, include_sensitive=True)
            appointment_data = {
                'id': appointment.id,
                'patient': {
                    'id': patient.id,
                    'user': {
                        'id': projected_user.get('id'),
                        'first_name': projected_user.get('first_name'),
                        'last_name': projected_user.get('last_name'),
                        'email': projected_user.get('email'),
                        'phone': projected_user.get('phone'),
                        'profile_picture': user.profile_picture
                    },
                    'blood_type': patient.blood_type,
                    'allergies': patient.allergies
                },
                'appointment_date': appointment.appointment_date,
                'appointment_date_formatted': appointment.appointment_date.strftime('%B %d, %Y') if appointment.appointment_date else None,
                'appointment_time': appointment.appointment_date.strftime('%H:%M') if appointment.appointment_date else None,
                'consultation_type': appointment.consultation_type,
                'symptoms': appointment.symptoms,
                'notes': appointment.notes,
                'status': appointment.status,
                'urgency': appointment.urgency,
                'created_at': appointment.created_at
            }
            
            # Categorize based on status and date
            if appointment.status == 'completed':
                completed_appointments.append(appointment_data)
            elif appointment.status == 'rescheduled':
                rescheduled_appointments.append(appointment_data)
            elif appointment.status == 'pending':
                pending_appointments.append(appointment_data)
            elif appointment.status in ['confirmed', 'scheduled']:
                upcoming_appointments.append(appointment_data)
            else:
                # Default to pending for unknown statuses
                pending_appointments.append(appointment_data)
        
        return render_template('doctor/patients.html',
                             upcoming=upcoming_appointments,
                             completed=completed_appointments,
                             rescheduled=rescheduled_appointments,
                             pending=pending_appointments)
    
    except Exception as e:
        print(f"Error loading patients: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading patients', 'error')
        return render_template('doctor/patients.html',
                             upcoming=[],
                             completed=[],
                             rescheduled=[],
                             pending=[])
@app.route('/api/doctor/patient/<int:patient_id>/latest-appointment')
@login_required
def get_patient_latest_appointment(patient_id):
    """Get the latest appointment for a specific patient with the current doctor"""
    if current_user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'error': 'Doctor profile not found'}), 404
    
    # Get latest appointment between this doctor and patient
    appointment = Appointment.query.filter_by(
        doctor_id=doctor.id,
        patient_id=patient_id
    ).order_by(Appointment.appointment_date.desc()).first()
    
    if appointment:
        return jsonify({
            'appointment_id': appointment.id,
            'appointment_date': appointment.appointment_date.isoformat(),
            'status': appointment.status
        })
    else:
        return jsonify({'appointment_id': None})

# Add endpoint for patient to get doctor's latest appointment
@app.route('/api/patient/doctor/<int:doctor_id>/latest-appointment')
@login_required
def get_doctor_latest_appointment(doctor_id):
    """Get the latest appointment for a specific doctor with the current patient"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    # Get latest appointment between this patient and doctor
    appointment = Appointment.query.filter_by(
        doctor_id=doctor_id,
        patient_id=patient.id
    ).order_by(Appointment.appointment_date.desc()).first()
    
    if appointment:
        return jsonify({
            'appointment_id': appointment.id,
            'appointment_date': appointment.appointment_date.isoformat(),
            'status': appointment.status
        })
    else:
        return jsonify({'appointment_id': None})

# Add endpoint to start new consultation
@app.route('/api/doctor/start-consultation', methods=['POST'])
@login_required
@csrf.exempt
def start_consultation():
    """Start a new consultation with a patient"""
    if current_user.role != 'doctor':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    data = request.get_json()
    patient_id = data.get('patient_id')
    
    if not patient_id:
        return jsonify({'success': False, 'error': 'Patient ID required'}), 400
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'success': False, 'error': 'Doctor profile not found'}), 404
    
    patient = db.session.get(Patient, patient_id)
    if not patient:
        return jsonify({'success': False, 'error': 'Patient not found'}), 404
    
    # Create a new appointment
    appointment = Appointment(
        patient_id=patient_id,
        doctor_id=doctor.id,
        appointment_date=now_eat(),
        consultation_type='message',
        status='confirmed'
    )
    
    db.session.add(appointment)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'appointment_id': appointment.id,
        'message': 'Consultation started successfully'
    })
@app.route('/api/patient/doctors')
@login_required
def get_patient_doctors():
    """Get doctors for patient communication page"""
    if current_user.role != 'patient':
        return jsonify({'error': 'Access denied'}), 403
    
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        return jsonify({'error': 'Patient profile not found'}), 404
    
    try:
        # Get appointments with doctor info
        appointments = db.session.query(
            Appointment,
            Doctor,
            User
        ).join(
            Doctor, Appointment.doctor_id == Doctor.id
        ).join(
            User, Doctor.user_id == User.id
        ).filter(
            Appointment.patient_id == patient.id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Group by doctor and get latest info
        doctors_map = {}
        for appointment, doctor, user in appointments:
            if doctor.id not in doctors_map:
                # Get last message
                last_message = Communication.query.filter_by(
                    appointment_id=appointment.id
                ).order_by(Communication.timestamp.desc()).first()
                
                # Check if doctor is online
                is_online = _is_user_online(user.id)
                
                # Get payment status
                payment = Payment.query.filter_by(
                    appointment_id=appointment.id
                ).order_by(Payment.created_at.desc()).first()
                
                doctors_map[doctor.id] = {
                    'doctor': {
                        'id': doctor.id,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'specialization': doctor.specialization,
                        'is_online': is_online,
                        'profile_picture_url': url_for('profile_picture', user_id=user.id, _external=True) if user else None
                    },
                    'last_appointment': {
                        'id': appointment.id,
                        'date': appointment.appointment_date.isoformat() if appointment.appointment_date else None,
                        'status': appointment.status
                    },
                    'last_message': last_message.content if last_message else None,
                    'last_message_time': last_message.timestamp.strftime('%H:%M') if last_message else None,
                    'unread_count': Communication.query.join(
                        Appointment, Communication.appointment_id == Appointment.id
                    ).filter(
                        Appointment.patient_id == patient.id,
                        Appointment.doctor_id == doctor.id,
                        Communication.is_read == False,
                        Communication.sender_id != current_user.id
                    ).count(),
                    'payment_status': payment.status if payment else 'pending'
                }
        
        return jsonify(list(doctors_map.values()))
        
    except Exception as e:
        print(f"Error in get_patient_doctors: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/user/<int:user_id>/basic')
@login_required
def get_user_basic(user_id):
    """Get basic user info for avatar"""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'name': 'User', 'initials': 'U'})
    
    # Generate initials
    initials = 'U'
    if user.first_name and user.last_name:
        initials = f"{user.first_name[0]}{user.last_name[0]}".upper()
    elif user.first_name:
        initials = user.first_name[0].upper()
    elif user.last_name:
        initials = user.last_name[0].upper()
    elif user.username:
        initials = user.username[0].upper()
    
    return jsonify({
        'name': user.get_display_name(),
        'initials': initials
    })
def _generate_room_token(appointment_id):
    """
    Produce a deterministic HMAC-SHA256 room token from the app secret key and appointment_id.
    The token is used ONLY as the server-side Socket.IO room name — never sent to clients.
    """
    secret = (app.config.get('SECRET_KEY') or os.getenv('SECRET_KEY') or 'dev-secret').encode()
    msg = f"consultation_room:{appointment_id}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def _generate_group_invite_token(appointment_id, patient_user_id):
    """One-time signed URL token for group session email invites."""
    secret = (app.config.get('SECRET_KEY') or os.getenv('SECRET_KEY') or 'dev-secret').encode()
    msg = f"group_invite:{appointment_id}:{patient_user_id}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def _get_or_create_consultation_room(appointment):
    """
    Retrieve existing ConsultationRoom for an appointment, or create it.
    Returns (room, created: bool).
    """
    room = ConsultationRoom.query.filter_by(appointment_id=appointment.id).first()
    if room:
        return room, False

    settings = _get_consultation_settings()
    open_before = settings.get('open_before_minutes', 0)
    open_after = settings.get('open_after_minutes', 0)

    appt_date = _coerce_eat(appointment.appointment_date)
    # 0 = no limit — use generous defaults so the room is effectively always open
    unlock_at = appt_date - timedelta(minutes=open_before if open_before > 0 else 525600)
    lock_at = appt_date + timedelta(minutes=open_after if open_after > 0 else 525600)
    token = _generate_room_token(appointment.id)

    room = ConsultationRoom(
        appointment_id=appointment.id,
        room_token=token,
        status='waiting',
        is_group_session=False,
        unlock_at=unlock_at,
        lock_at=lock_at,
    )
    db.session.add(room)
    db.session.commit()
    return room, True


def _check_room_access(appointment, user):
    """
    Returns (allowed: bool, reason: str).
    Rules:
    - Payment must be 'paid'
    - Appointment status must be in pending/confirmed/ongoing/rescheduled
    - Room must be within time window  OR  user is admin/doctor (grace)
    - User must be associated with the appointment
    """
    if not appointment:
        return False, 'appointment_not_found'

    # Associate check
    if user.role == 'patient':
        patient = Patient.query.filter_by(user_id=user.id).first()
        if not patient or appointment.patient_id != patient.id:
            return False, 'not_your_appointment'
    elif user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=user.id).first()
        if not doctor or appointment.doctor_id != doctor.id:
            return False, 'not_your_appointment'
    elif user.role != 'admin':
        return False, 'unauthorized_role'

    # Payment gate (skip for admin)
    # TODO: Re-enable payment gate once consultation room is fully tested
    # if user.role != 'admin':
    #     try:
    #         from models import Payment as _Pay
    #         payment = _Pay.query.filter_by(appointment_id=appointment.id, status='paid').first()
    #     except Exception:
    #         payment = None
    #     payment_status = 'paid' if payment else (getattr(appointment, 'payment_status', None) or 'unpaid')
    #     if payment_status != 'paid':
    #         return False, 'payment_required'

    # Status gate
    # TODO: Re-enable status gate once consultation room is fully tested
    # allowed_statuses = {'pending', 'confirmed', 'ongoing', 'rescheduled'}
    # if (appointment.status or '').lower() not in allowed_statuses:
    #     return False, 'appointment_not_active'

    return True, 'ok'


def _send_group_invite_emails(doctor, room, invited_appointments):
    """Send group consultation invite emails to each patient in invited_appointments."""
    for appt in invited_appointments:
        try:
            patient_user = appt.patient.user if appt.patient else None
            if not patient_user:
                continue
            invite_token = _generate_group_invite_token(appt.id, patient_user.id)
            join_url = url_for('join_consultation_room_via_invite',
                               appointment_id=appt.id, token=invite_token, _external=True)
            appt_dt = _coerce_eat(appt.appointment_date)
            _send_patient_appointment_email(
                appointment=appt,
                email_key=f'group_invite_{room.id}',
                subject=f'Group Consultation Invitation – Dr. {doctor.user.first_name} {doctor.user.last_name}',
                template_name='email/group_consultation_invite.html',
                template_context={
                    'doctor': doctor,
                    'appointment': appt,
                    'join_url': join_url,
                    'appt_time': appt_dt.strftime('%B %d, %Y at %I:%M %p') if appt_dt else 'Scheduled',
                    'room': room,
                },
                dedupe=False,
            )
        except Exception as e:
            app.logger.warning(f'Group invite email failed for appt {appt.id}: {e}')


# ============================================
# CONSULTATION ROOM HTTP ROUTES
# ============================================

@app.route('/consultation-room/<int:appointment_id>')
@login_required
def consultation_room(appointment_id):
    """Main consultation room page — replaces old video-call and voice-call pages."""
    appointment = Appointment.query.get_or_404(appointment_id)
    observe_mode = request.args.get('observer') == '1' and current_user.role == 'admin'

    allowed, reason = _check_room_access(appointment, current_user)
    # For the page render we let even locked/unpaid users land on the page
    # so they see the proper "locked" or "payment required" UI.
    # Hard block only unauthorized roles.
    if reason in ('not_your_appointment', 'unauthorized_role'):
        flash('You do not have access to this consultation room.', 'danger')
        return redirect(url_for('index'))

    room, _ = _get_or_create_consultation_room(appointment)

    _, live_call = find_active_call(appointment_id=appointment.id)
    call_members = _build_call_page_members(
        appointment, call_info=live_call, observe_mode=observe_mode
    )

    # Determine payment status for the template
    try:
        from models import Payment as _Pay
        payment = _Pay.query.filter_by(appointment_id=appointment.id, status='paid').first()
        payment_status = 'paid' if payment else (getattr(appointment, 'payment_status', None) or 'unpaid')
    except Exception:
        payment_status = getattr(appointment, 'payment_status', None) or 'unpaid'

    return render_template(
        'communication/consultation_room.html',
        appointment=appointment,
        room=room,
        observe_mode=observe_mode,
        payment_status=payment_status,
        active_call=_serialize_active_call(live_call) if live_call else None,
        call_members=call_members,
    )


@app.route('/consultation-room/<int:appointment_id>/join/<token>')
@login_required
def join_consultation_room_via_invite(appointment_id, token):
    """
    Deep-link from a group session email invite.
    Validates HMAC token then redirects to the consultation room.
    """
    expected = _generate_group_invite_token(appointment_id, current_user.id)
    if not hmac.compare_digest(expected, token):
        flash('Invalid or expired invitation link.', 'danger')
        return redirect(url_for('index'))
    return redirect(url_for('consultation_room', appointment_id=appointment_id))


@app.route('/api/consultation-room/<int:appointment_id>/status')
@login_required
def get_consultation_room_status(appointment_id):
    """
    Poll endpoint — returns room state, time-lock info, and participant count.
    Called every 30 s from the locked-lobby UI.
    """
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        return jsonify({'success': False, 'error': 'not_found'}), 404

    allowed, reason = _check_room_access(appointment, current_user)
    if reason in ('not_your_appointment', 'unauthorized_role'):
        return jsonify({'success': False, 'error': reason}), 403

    room, _ = _get_or_create_consultation_room(appointment)

    # Live participant count from session room memberships
    room_key = f'consultation:{room.room_token}'
    participants = list(room_memberships.get(room_key, {}).values())

    return jsonify({
        'success': True,
        'room': room.to_public_dict(),
        'payment_status': reason != 'payment_required' and 'paid' or 'unpaid',
        'participants': participants,
        'participant_count': len(participants),
    })


@app.route('/api/consultation-room/<int:appointment_id>/end', methods=['POST'])
@login_required
def end_consultation_room(appointment_id):
    """Doctor or admin can formally end the session."""
    if current_user.role not in ('doctor', 'admin'):
        return jsonify({'success': False, 'error': 'forbidden'}), 403

    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        return jsonify({'success': False, 'error': 'not_found'}), 404

    room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
    if not room:
        return jsonify({'success': False, 'error': 'room_not_found'}), 404

    data = request.get_json(silent=True) or {}
    mark_complete = bool(data.get('mark_complete', True))

    room.status = 'ended'
    room.ended_at = now_eat()
    room.ended_by_user_id = current_user.id
    db.session.add(room)

    if mark_complete and appointment.status not in ('completed', 'cancelled'):
        appointment.status = 'completed'
        db.session.add(appointment)

    db.session.commit()

    # Notify all room participants via Socket.IO
    room_socket_name = f'consultation:{room.room_token}'
    socketio.emit('consultation_room_ended', {
        'appointment_id': appointment_id,
        'ended_by': current_user.id,
        'mark_complete': mark_complete,
    }, room=room_socket_name)

    if mark_complete:
        try:
            _send_appointment_outcome_email(appointment, outcome='completed')
        except Exception as e:
            app.logger.warning(f'Post-consultation email failed: {e}')

    return jsonify({'success': True})


@app.route('/api/doctor/consultation-room/<int:appointment_id>/group-invite', methods=['POST'])
@login_required
def group_consultation_invite(appointment_id):
    """
    Doctor selects additional patient appointment IDs to merge into a group session.
    All selected patients receive an invitation email.
    """
    if current_user.role != 'doctor':
        return jsonify({'success': False, 'error': 'forbidden'}), 403

    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        return jsonify({'success': False, 'error': 'not_found'}), 404

    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor or appointment.doctor_id != doctor.id:
        return jsonify({'success': False, 'error': 'not_your_appointment'}), 403

    data = request.get_json(silent=True) or {}
    invited_ids = data.get('appointment_ids', [])
    if not isinstance(invited_ids, list) or not invited_ids:
        return jsonify({'success': False, 'error': 'no_appointments_selected'}), 400

    # Validate all invited appointments belong to this doctor and are paid+confirmed
    invited_appointments = []
    invalid = []
    for inv_id in invited_ids:
        try:
            inv_appt = db.session.get(Appointment, int(inv_id))
        except Exception:
            inv_appt = None
        if not inv_appt or inv_appt.doctor_id != doctor.id:
            invalid.append(inv_id)
            continue
        invited_appointments.append(inv_appt)

    if invalid:
        return jsonify({
            'success': False,
            'error': 'invalid_appointments',
            'invalid_ids': invalid,
        }), 400

    # Get or create the primary room, mark as group session
    room, _ = _get_or_create_consultation_room(appointment)
    all_ids = list({appointment.id} | {a.id for a in invited_appointments})
    room.is_group_session = True
    room.group_appointment_ids = all_ids
    db.session.add(room)
    db.session.commit()

    # Send invite emails
    _send_group_invite_emails(doctor, room, invited_appointments)

    return jsonify({
        'success': True,
        'group_appointment_ids': all_ids,
        'invited_count': len(invited_appointments),
    })


@app.route('/api/consultation-room/<int:appointment_id>/notes', methods=['PATCH'])
@login_required
def save_consultation_notes(appointment_id):
    """Doctor saves live notes during the session (debounced from frontend)."""
    if current_user.role not in ('doctor', 'admin'):
        return jsonify({'success': False, 'error': 'forbidden'}), 403

    room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
    if not room:
        return jsonify({'success': False, 'error': 'room_not_found'}), 404

    data = request.get_json(silent=True) or {}
    notes = str(data.get('notes', '') or '')[:20000]  # cap at 20k chars
    room.session_notes = notes
    room.updated_at = now_eat()
    db.session.add(room)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/consultation-room/<int:appointment_id>/recording-consent', methods=['POST'])
@login_required
def set_recording_consent(appointment_id):
    """Patient or doctor sets their recording consent flag."""
    room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
    if not room:
        return jsonify({'success': False, 'error': 'room_not_found'}), 404

    data = request.get_json(silent=True) or {}
    consent = bool(data.get('consent', False))

    if current_user.role == 'doctor':
        room.recording_consent_doctor = consent
    elif current_user.role == 'patient':
        room.recording_consent_patient = consent
    else:
        return jsonify({'success': False, 'error': 'forbidden'}), 403

    db.session.add(room)
    db.session.commit()

    both_consented = room.recording_consent_doctor and room.recording_consent_patient
    room_socket_name = f'consultation:{room.room_token}'
    socketio.emit('recording_consent_update', {
        'appointment_id': appointment_id,
        'doctor_consented': room.recording_consent_doctor,
        'patient_consented': room.recording_consent_patient,
        'both_consented': both_consented,
    }, room=room_socket_name)

    return jsonify({'success': True, 'both_consented': both_consented})


# ============================================
# VOICE CALL ROUTE (new implementation below in Socket.IO)
# ============================================

@app.route('/voice-call/<int:appointment_id>')
@login_required
def voice_call_page(appointment_id):
    """Dedicated voice call page with full-featured UI"""
    appointment = Appointment.query.get_or_404(appointment_id)
    # Verify user has access
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or appointment.patient_id != patient.id:
            return redirect(url_for('index'))
    elif current_user.role == 'doctor':
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor or appointment.doctor_id != doctor.id:
            return redirect(url_for('index'))
    elif current_user.role != 'admin':
        return redirect(url_for('index'))

    other_user = appointment.patient.user if current_user.role == 'doctor' else appointment.doctor.user
    _, live_call = find_active_call(appointment_id=appointment.id)
    return render_template(
        'communication/voice_call.html',
        appointment=appointment,
        other_user=other_user,
        active_call=_serialize_active_call(live_call) if live_call else None,
    )

@app.route('/doctor/<int:doctor_id>')
@login_required
def doctor_profile(doctor_id):
    """Doctor profile page"""
    doctor = Doctor.query.get_or_404(doctor_id)
    user = User.query.get_or_404(doctor.user_id)
    
    return render_template('doctor/profile.html', doctor=doctor, user=user)


@app.route('/doctors')
def doctors():
    """Public list of available doctors"""
    doctors = db.session.query(Doctor, User).join(
        User, Doctor.user_id == User.id
    ).filter(Doctor.availability == True).all()

    return render_template('doctors.html', doctors=doctors)
@app.route('/api/prescription/form')
@login_required
def get_prescription_form():
    """Get prescription form HTML"""
    if current_user.role != 'doctor':
        return jsonify({'error': 'Access denied'}), 403
    
    patient_id = request.args.get('patient_id')
    appointment_id = request.args.get('appointment_id')
    
    return '''
    <form id="prescriptionFormData">
        <input type="hidden" name="patient_id" value="''' + (patient_id or '') + '''">
        <input type="hidden" name="appointment_id" value="''' + (appointment_id or '') + '''">
        
        <div class="mb-3">
            <label class="form-label">Medication Name</label>
            <input type="text" class="form-control" name="medication" required>
        </div>
        
        <div class="mb-3">
            <label class="form-label">Dosage</label>
            <input type="text" class="form-control" name="dosage" placeholder="e.g., 500mg twice daily" required>
        </div>
        
        <div class="mb-3">
            <label class="form-label">Duration</label>
            <input type="text" class="form-control" name="duration" placeholder="e.g., 7 days" required>
        </div>
        
        <div class="mb-3">
            <label class="form-label">Instructions</label>
            <textarea class="form-control" name="instructions" rows="3" placeholder="Additional instructions..."></textarea>
        </div>
        
        <div class="mb-3">
            <label class="form-label">Refills</label>
            <input type="number" class="form-control" name="refills" min="0" max="5" value="0">
        </div>
        
        <div class="text-end">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-primary" id="savePrescriptionBtn">Save Prescription</button>
        </div>
    </form>
    '''

# Add endpoint to save prescription
@app.route('/api/prescription/save', methods=['POST'])
@login_required
@csrf.exempt
def save_prescription():
    """Save a new prescription"""
    if current_user.role != 'doctor':
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    patient_id = request.form.get('patient_id')
    appointment_id = request.form.get('appointment_id')
    medication = request.form.get('medication')
    dosage = request.form.get('dosage')
    instructions = request.form.get('instructions')
    
    if not all([patient_id, appointment_id, medication, dosage]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    doctor = Doctor.query.filter_by(user_id=current_user.id).first()
    if not doctor:
        return jsonify({'success': False, 'error': 'Doctor profile not found'}), 404
    
    # Create prescription
    prescription = Prescription(
        doctor_id=doctor.id,
        patient_id=patient_id,
        appointment_id=appointment_id,
        medication=medication,
        dosage=dosage,
        instructions=instructions
    )
    
    db.session.add(prescription)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'prescription_id': prescription.id,
        'message': 'Prescription saved successfully'
    })


@app.route('/prescription/<int:prescription_id>')
@login_required
def view_prescription(prescription_id):
    """Render a prescription for viewing (patient/doctor/admin)."""
    prescription = Prescription.query.get_or_404(prescription_id)

    # Access control: allow patient owner, prescribing doctor, or admin
    if current_user.role == 'patient' and prescription.patient.user_id != current_user.id:
        return redirect(url_for('index'))
    if current_user.role == 'doctor' and prescription.doctor.user_id != current_user.id:
        # allow doctor to view only their own prescriptions
        return redirect(url_for('index'))

    # Determine expiry
    now = now_eat()
    prescription_expired = bool(prescription.is_expired or (prescription.expiry_date and prescription.expiry_date < now))

    # Log audit: viewed
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=(current_user.id if current_user.is_authenticated else None), action='viewed')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return render_template('patient/prescription.html', prescription=prescription, prescription_expired=prescription_expired)


@app.route('/prescription/<int:prescription_id>/print')
@login_required
def print_prescription(prescription_id):
    prescription = Prescription.query.get_or_404(prescription_id)

    # Access control similar to view_prescription
    if current_user.role == 'patient' and prescription.patient.user_id != current_user.id:
        return redirect(url_for('index'))
    if current_user.role == 'doctor' and prescription.doctor.user_id != current_user.id:
        return redirect(url_for('index'))

    now = now_eat()
    prescription_expired = bool(prescription.is_expired or (prescription.expiry_date and prescription.expiry_date < now))

    # Render same template but include print-on-load in the template
    # Audit print action
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=(current_user.id if current_user.is_authenticated else None), action='printed')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return render_template('patient/prescription.html', prescription=prescription, prescription_expired=prescription_expired, print_mode=True)


@app.route('/prescription/<int:prescription_id>/download')
@login_required
def download_prescription_pdf(prescription_id):
    """Generate a PDF for the prescription and send it to the user."""
    prescription = Prescription.query.get_or_404(prescription_id)

    # Access control
    if current_user.role == 'patient' and prescription.patient.user_id != current_user.id:
        return redirect(url_for('index'))
    if current_user.role == 'doctor' and prescription.doctor.user_id != current_user.id:
        return redirect(url_for('index'))

    # Richer PDF: include logo, clinic header, doctor's signature (if available) and QR code
    from reportlab.lib.pagesizes  import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
    import io, qrcode

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Clinic logo
    try:
        logo_path = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), 'logo.png')
        if os.path.exists(logo_path):
            logo = ImageReader(logo_path)
            c.drawImage(logo, 50, height - 90, width=120, preserveAspectRatio=True, mask='auto')
    except Exception:
        pass

    # Clinic header
    c.setFont('Helvetica-Bold', 18)
    c.drawString(200, height - 60, 'Makokha Medical Centre')
    c.setFont('Helvetica', 11)
    c.drawString(200, height - 76, 'Telemedicine & Clinical Services')

    y = height - 110
    c.setFont('Helvetica', 11)
    c.drawString(50, y, f'Date: {prescription.created_at.strftime("%Y-%m-%d %H:%M UTC")}')
    y -= 18
    doctor_name = getattr(prescription.doctor.user, 'first_name', '') or ''
    doctor_last = getattr(prescription.doctor.user, 'last_name', '') or ''
    c.drawString(50, y, f'Prescribed by: Dr. {doctor_name} {doctor_last}')
    y -= 26

    # Medication details
    c.setFont('Helvetica-Bold', 12)
    c.drawString(50, y, 'Medication:')
    c.setFont('Helvetica', 12)
    c.drawString(150, y, prescription.medication)
    y -= 20
    c.setFont('Helvetica-Bold', 12)
    c.drawString(50, y, 'Dosage:')
    c.setFont('Helvetica', 12)
    c.drawString(150, y, prescription.dosage)
    y -= 24

    c.setFont('Helvetica-Bold', 12)
    c.drawString(50, y, 'Instructions:')
    y -= 16
    text = c.beginText(50, y)
    text.setFont('Helvetica', 11)
    for line in (prescription.instructions or '').split('\n'):
        text.textLine(line)
    c.drawText(text)

    # QR code linking to the prescription verify/view URL
    try:
        verify_url = request.host_url.rstrip('/') + url_for('view_prescription', prescription_id=prescription.id)
        qr = qrcode.make(verify_url)
        qr_buf = io.BytesIO()
        qr.save(qr_buf, format='PNG')
        qr_buf.seek(0)
        qr_img = ImageReader(qr_buf)
        c.drawImage(qr_img, width - 150, 80, width=90, preserveAspectRatio=True, mask='auto')
    except Exception:
        pass

    # Signature image if available under uploads/signatures/doctor_{id}.png
    try:
        sig_path = os.path.join(app.root_path, app.config.get('UPLOAD_FOLDER', 'static/uploads'), 'signatures', f'doctor_{prescription.doctor.id}.png')
        if os.path.exists(sig_path):
            sig = ImageReader(sig_path)
            c.drawImage(sig, 50, 80, width=180, preserveAspectRatio=True, mask='auto')
        else:
            c.setFont('Helvetica-Oblique', 12)
            c.drawString(50, 110, f'Signed: Dr. {doctor_name} {doctor_last}')
    except Exception:
        c.setFont('Helvetica-Oblique', 12)
        c.drawString(50, 110, f'Signed: Dr. {doctor_name} {doctor_last}')

    # If expired, add red rubber-stamp
    now = now_eat()
    expired = bool(prescription.is_expired or (prescription.expiry_date and prescription.expiry_date < now))
    if expired:
        c.setFillColorRGB(1, 0, 0)
        c.setFont('Helvetica-Bold', 48)
        c.saveState()
        c.translate(300, 300)
        c.rotate(30)
        c.drawCentredString(0, 0, 'EXPIRED')
        c.restoreState()

    c.showPage()
    c.save()
    buffer.seek(0)

    # Audit download
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=(current_user.id if current_user.is_authenticated else None), action='downloaded')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return send_file(buffer, as_attachment=True, download_name=f'prescription_{prescription.id}.pdf', mimetype='application/pdf')


@app.route('/prescription/<int:prescription_id>/expire', methods=['POST'])
@login_required
def expire_prescription(prescription_id):
    """Mark a prescription as expired (e.g., by dispensing person)."""
    prescription = Prescription.query.get_or_404(prescription_id)
    # Access control -- allow admin or doctor or designated staff
    if current_user.role not in ('admin', 'doctor'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    prescription.is_expired = True
    prescription.expired_by = current_user.id
    prescription.dispensed_at = now_eat()
    db.session.commit()
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=current_user.id, action='expired')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'success': True})


@app.route('/prescription/<int:prescription_id>/dispense', methods=['POST'])
@login_required
def dispense_prescription(prescription_id):
    """Mark prescription as dispensed/signed by dispensing person."""
    prescription = Prescription.query.get_or_404(prescription_id)
    if current_user.role not in ('admin', 'doctor'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    prescription.dispensed_by = current_user.id
    prescription.dispensed_at = now_eat()
    db.session.commit()
    try:
        audit = PrescriptionAudit(prescription_id=prescription.id, user_id=current_user.id, action='dispensed')
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'success': True})


@app.route('/doctor/prescribed')
@login_required
def doctor_prescribed_list():
    if current_user.role != 'doctor':
        return redirect(url_for('index'))

    doctor = Doctor.query.filter_by(user_id=current_user.id).first_or_404()
    prescriptions = Prescription.query.filter_by(doctor_id=doctor.id).order_by(Prescription.created_at.desc()).all()
    return render_template('doctor/prescribed.html', prescriptions=prescriptions)
# ============================================
# SOCKET.IO EVENT HANDLERS - REAL-TIME COMMUNICATION
# ============================================

@socketio.on_error_default
def default_error_handler(e):
    """Handle Socket.IO errors"""
    print(f'Socket.IO error: {e}')
    import traceback
    traceback.print_exc()

# Add this route BEFORE your main Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    """Handle Socket.IO connection"""
    if current_user.is_authenticated:
        sid = request.sid
        _add_user_socket(current_user.id, sid)
        user_last_seen[current_user.id] = now_eat().isoformat()
        # Ensure user joins their personal room for direct emits
        try:
            join_room(f'user_{current_user.id}')
        except Exception:
            pass
        _set_presence(current_user.id, online=True)
        _metric_incr('connections', 1)
        _metric_set('online_users', _count_online_users())
        
        emit('connection_response', {'data': 'Connected to server'})
        _log_event('socket_connect', user_id=current_user.id, sid=request.sid, online_users=_count_online_users())
        print(f'User {current_user.id} connected: {request.sid}')
        try:
            print(f'Current user_sockets mapping ({len(user_sockets)}): {user_sockets}')
        except Exception:
            pass
        return True
    return False


# Make ICE servers available to templates via context processor
@app.context_processor
def inject_ice_servers():
    try:
        ice = app.config.get('ICE_SERVERS', [{'urls': 'stun:stun.l.google.com:19302'}])
        return {'ice_servers': ice}
    except Exception:
        return {'ice_servers': [{'urls': 'stun:stun.l.google.com:19302'}]}

# Also add this route for health check
@app.route('/socket.io/')
def socketio_health():
    """Handle Socket.IO health check"""
    return jsonify({'status': 'ok', 'socketio': 'enabled'})
@socketio.on('disconnect')
def handle_disconnect(reason=None):
    """Handle user disconnection with cleanup."""
    sid = request.sid
    try:
        # Remove this sid from any user's socket list
        for uid, sids in list(user_sockets.items()):
            try:
                sids_list = _normalize_sid_list(sids)
                if sid in sids_list:
                    _remove_user_socket(uid, sid)
                    if not _get_user_sockets(uid):
                        user_last_seen[uid] = now_eat().isoformat()
                        _set_presence(uid, online=False)
            except Exception:
                user_sockets.pop(uid, None)

        # If current_user is authenticated, update last seen and cleanup active_calls
        if current_user.is_authenticated:
            user_id = current_user.id
            user_last_seen[user_id] = now_eat().isoformat()
            # Clean up active_calls entries referencing this user
            for apt_id, users in list(active_calls.items()):
                try:
                    if isinstance(users, dict) and user_id in users:
                        del users[user_id]
                        if not users:
                            del active_calls[apt_id]
                except Exception:
                    pass
            
            # Broadcast user disconnect to any rooms they were in
            try:
                emit('user_disconnected', {
                    'user_id': user_id,
                    'user_name': safe_display_name(current_user),
                    'timestamp': now_eat().isoformat()
                }, broadcast=True)
            except Exception:
                pass
            _metric_incr('connections', -1)
            _metric_set('online_users', _count_online_users())
            _log_event('socket_disconnect', user_id=user_id, sid=sid, online_users=_count_online_users())

        try:
            print(f'User disconnected (sid={sid}). Current user_sockets mapping ({len(user_sockets)}): {user_sockets}')
        except Exception:
            pass

    except Exception as e:
        print(f'Error in handle_disconnect: {e}')

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    try:
        # Simple check without database query to avoid threading issues
        return jsonify({
            'status': 'healthy',
            'timestamp': now_eat().isoformat(),
            'service': 'telemedicine-platform'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': now_eat().isoformat()
        }), 500

@socketio.on('user_online_status')
def handle_user_online_status(data):
    """Handle user online/offline status updates"""
    if not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'user_online_status', 30, 60):
        return
    
    user_id = current_user.id
    is_online = data.get('is_online', True)
    
    if is_online:
        # Ensure list semantics for user_sockets (support multiple tabs/devices)
        sid = request.sid
        _add_user_socket(user_id, sid)
        user_last_seen[user_id] = now_eat().isoformat()
        _set_presence(user_id, online=True)
        _metric_set('online_users', _count_online_users())
        
        # Notify relevant users based on role
        if current_user.role == 'doctor':
            # Notify all patients who have appointments with this doctor
            doctor = Doctor.query.filter_by(user_id=user_id).first()
            if doctor:
                appointments = Appointment.query.filter_by(doctor_id=doctor.id).all()
                patient_ids = set([app.patient_id for app in appointments])
                
                for patient_id in patient_ids:
                    patient = db.session.get(Patient, patient_id)
                    if patient:
                        # Emit to the patient's personal room
                        socketio.emit('doctor_online', {
                            'doctor_id': doctor.id,
                            'doctor_name': current_user.get_display_name()
                        }, room=f'user_{patient.user_id}')
        
        elif current_user.role == 'patient':
            # Notify all doctors who have appointments with this patient
            patient = Patient.query.filter_by(user_id=user_id).first()
            if patient:
                appointments = Appointment.query.filter_by(patient_id=patient.id).all()
                doctor_ids = set([app.doctor_id for app in appointments])
                
                for doctor_id in doctor_ids:
                    doctor = db.session.get(Doctor, doctor_id)
                    if doctor:
                        socketio.emit('patient_online', {
                            'patient_id': patient.id,
                            'patient_name': current_user.get_display_name()
                        }, room=f'user_{doctor.user_id}')
    
    else:
        _set_user_sockets(user_id, [])
        _set_presence(user_id, online=False)
        _metric_set('online_users', _count_online_users())
        
        # Notify relevant users about offline status
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=user_id).first()
            if doctor:
                appointments = Appointment.query.filter_by(doctor_id=doctor.id).all()
                patient_ids = set([app.patient_id for app in appointments])
                
                for patient_id in patient_ids:
                    patient = db.session.get(Patient, patient_id)
                    if patient:
                        socketio.emit('doctor_offline', {
                            'doctor_id': doctor.id
                        }, room=f'user_{patient.user_id}')
        
        elif current_user.role == 'patient':
            patient = Patient.query.filter_by(user_id=user_id).first()
            if patient:
                appointments = Appointment.query.filter_by(patient_id=patient.id).all()
                doctor_ids = set([app.doctor_id for app in appointments])
                
                for doctor_id in doctor_ids:
                    doctor = db.session.get(Doctor, doctor_id)
                    if doctor:
                        socketio.emit('patient_offline', {
                            'patient_id': patient.id
                        }, room=f'user_{doctor.user_id}')
# Doctor marks consultation complete
@app.route('/api/appointments/<int:appointment_id>/complete', methods=['POST'])
@login_required
def mark_appointment_complete(appointment_id):
    try:
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return jsonify({'error': 'appointment_not_found'}), 404

        # Only the doctor for this appointment may mark it complete
        try:
            doc = db.session.get(Doctor, appointment.doctor_id)
            doctor_user_id = getattr(doc, 'user_id', None) if doc else None
        except Exception:
            doctor_user_id = None

        if current_user.id != doctor_user_id:
            return jsonify({'error': 'forbidden'}), 403

        # Optional notes may be provided by the doctor
        data = request.get_json(silent=True) or {}
        notes = data.get('notes') if isinstance(data, dict) else None
        if notes is not None:
            try:
                appointment.notes = notes
            except Exception:
                pass

        appointment.status = 'completed'
        appointment.call_status = 'ended'
        db.session.add(appointment)
        db.session.commit()
        _send_appointment_outcome_email(appointment, outcome='completed')

        # Audit log: appointment completed by doctor
        try:
            audit = AuditLog(user_id=current_user.id, action='appointment_completed', description=f'Doctor marked appointment {appointment_id} complete', ip_address=request.remote_addr)
            db.session.add(audit)
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Notify patient and doctor sockets if present
        try:
            patient = db.session.get(Patient, appointment.patient_id)
            patient_user_id = getattr(patient, 'user_id', None) if patient else None
            payload = {'appointment_id': appointment_id, 'status': 'completed'}
            if doctor_user_id:
                socketio.emit('appointment_marked_complete', payload, room=f'user_{doctor_user_id}')
            if patient_user_id:
                socketio.emit('appointment_marked_complete', payload, room=f'user_{patient_user_id}')
        except Exception:
            pass

        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to mark appointment complete')
        return jsonify({'success': False, 'error': str(e)}), 500

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    """Handle WebRTC offer"""
    if not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'webrtc_offer', 20, 60):
        emit('error', {'message': 'rate_limited'})
        return
    
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    appointment = _socket_get_appointment(appointment_id, error_event='error', require_payment=True)
    if not appointment:
        return
    call_id = data.get('call_id') if isinstance(data, dict) else None
    target_user_id = data.get('target_user_id') if isinstance(data, dict) else None
    call_type = _resolve_call_type(call_id=call_id, appointment_id=appointment_id, data=data)

    payload = {
        'appointment_id': appointment_id,
        'call_id': call_id,
        'offer': data.get('offer'),
        'sender_id': current_user.id,
        'target_user_id': target_user_id,
        'room_id': _resolve_call_room(appointment_id=appointment_id, call_id=call_id, call_type=call_type),
    }
    _emit_call_signal(
        'webrtc_offer',
        payload,
        appointment_id=appointment_id,
        call_id=call_id,
        call_type=call_type,
        target_user_id=target_user_id,
    )

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    """Handle WebRTC answer"""
    if not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'webrtc_answer', 20, 60):
        emit('error', {'message': 'rate_limited'})
        return
    
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    appointment = _socket_get_appointment(appointment_id, error_event='error', require_payment=True)
    if not appointment:
        return
    call_id = data.get('call_id') if isinstance(data, dict) else None
    target_user_id = data.get('target_user_id') if isinstance(data, dict) else None
    call_type = _resolve_call_type(call_id=call_id, appointment_id=appointment_id, data=data)

    payload = {
        'appointment_id': appointment_id,
        'call_id': call_id,
        'answer': data.get('answer'),
        'sender_id': current_user.id,
        'target_user_id': target_user_id,
        'room_id': _resolve_call_room(appointment_id=appointment_id, call_id=call_id, call_type=call_type),
    }
    _emit_call_signal(
        'webrtc_answer',
        payload,
        appointment_id=appointment_id,
        call_id=call_id,
        call_type=call_type,
        target_user_id=target_user_id,
    )

@socketio.on('webrtc_ice_candidate')
def handle_webrtc_ice_candidate(data):
    """Handle WebRTC ICE candidate"""
    if not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'webrtc_ice_candidate', 600, 60):
        emit('error', {'message': 'rate_limited'})
        return
    
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    appointment = _socket_get_appointment(appointment_id, error_event='error', require_payment=True)
    if not appointment:
        return
    call_id = data.get('call_id') if isinstance(data, dict) else None
    target_user_id = data.get('target_user_id') if isinstance(data, dict) else None
    call_type = _resolve_call_type(call_id=call_id, appointment_id=appointment_id, data=data)

    payload = {
        'appointment_id': appointment_id,
        'call_id': call_id,
        'candidate': data.get('candidate'),
        'sender_id': current_user.id,
        'target_user_id': target_user_id,
        'room_id': _resolve_call_room(appointment_id=appointment_id, call_id=call_id, call_type=call_type),
    }
    _emit_call_signal(
        'webrtc_ice_candidate',
        payload,
        appointment_id=appointment_id,
        call_id=call_id,
        call_type=call_type,
        target_user_id=target_user_id,
    )

# ============================================================================
# ENHANCED SOCKET.IO HANDLERS FOR NEW COMMUNICATION MODELS
# ============================================================================

@socketio.on('presence:update')
def handle_presence_update(data):
    """Handle presence updates and persist to UserPresence model"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        status = data.get('status', 'online')  # online, away, idle, busy, offline, do_not_disturb
        current_call_id = data.get('current_call_id')
        current_appointment_id = data.get('current_appointment_id')
        
        # Upsert UserPresence record
        presence = UserPresence.query.filter_by(user_id=current_user.id).first()
        if not presence:
            presence = UserPresence(user_id=current_user.id)
        
        presence.status = status
        presence.current_call_id = current_call_id
        presence.current_appointment_id = current_appointment_id
        presence.last_heartbeat = now_eat()
        presence.last_seen = now_eat()
        
        db.session.add(presence)
        db.session.commit()
        
        # Broadcast presence update to all connected clients
        emit('presence:updated', {
            'user_id': current_user.id,
            'status': status,
            'last_seen': presence.last_seen.isoformat(),
            'current_call_id': current_call_id,
            'current_appointment_id': current_appointment_id
        }, broadcast=True)
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Presence update failed: {str(e)}'})
@socketio.on('call:initiate')
def handle_call_initiate_enhanced(data):
    """Route call initiation to the voice call handler."""
    if not current_user or not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'call_initiate', 6, 60):
        emit('error', {'message': 'rate_limited'})
        return
    return handle_initiate_voice_call(data)


@socketio.on('call:accept')
def handle_call_accept_enhanced(data):
    """Route call acceptance to the voice call handler."""
    if not current_user or not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'call_accept', 12, 60):
        emit('error', {'message': 'rate_limited'})
        return
    return handle_accept_voice_call(data)


@socketio.on('call:end')
def handle_call_end_enhanced(data):
    """Route call end to the voice call handler."""
    if not current_user or not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'call_end', 20, 60):
        emit('error', {'message': 'rate_limited'})
        return
    return handle_end_voice_call(data)


@socketio.on('call:reject')
def handle_call_reject_enhanced(data):
    """Route call rejection to the voice call handler."""
    if not current_user or not current_user.is_authenticated:
        return
    return handle_reject_voice_call(data)


@socketio.on('quality:metrics')
def handle_quality_metrics(data):
    """Handle call quality metrics submission"""
    try:
        if not current_user or not current_user.is_authenticated:
            return
        
        call_id = data.get('call_id')
        rtt = data.get('rtt')
        packet_loss = data.get('packet_loss')
        jitter = data.get('jitter')
        audio_bitrate = data.get('audio_bitrate')
        video_bitrate = data.get('video_bitrate')
        video_resolution = data.get('video_resolution')
        video_framerate = data.get('video_framerate')
        cpu_usage = data.get('cpu_usage')
        memory_usage = data.get('memory_usage')
        audio_quality = data.get('audio_quality', 'good')
        video_quality = data.get('video_quality', 'good')
        
        # Get call history for reference
        call_history = CallHistory.query.filter_by(call_id=call_id).first()
        if not call_history:
            emit('error', {'message': 'Call not found'})
            return
        
        # Create quality metrics record
        metrics = CallQualityMetrics(
            call_id=call_id,
            user_id=current_user.id,
            rtt=rtt,
            packet_loss=packet_loss,
            jitter=jitter,
            audio_bitrate=audio_bitrate,
            video_bitrate=video_bitrate,
            video_resolution=video_resolution,
            video_framerate=video_framerate,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            audio_quality=audio_quality,
            video_quality=video_quality,
            timestamp=now_eat()
        )
        
        db.session.add(metrics)
        
        # Update call_history quality_metrics JSON field
        try:
            existing_metrics = json.loads(call_history.quality_metrics or '{}')
        except:
            existing_metrics = {}
        
        existing_metrics[str(current_user.id)] = {
            'rtt': rtt,
            'packet_loss': packet_loss,
            'jitter': jitter,
            'audio_bitrate': audio_bitrate,
            'video_bitrate': video_bitrate,
            'audio_quality': audio_quality,
            'video_quality': video_quality
        }
        
        call_history.quality_metrics = json.dumps(existing_metrics)
        
        db.session.commit()
        
        emit('quality:recorded', {
            'call_id': call_id,
            'user_id': current_user.id,
            'audio_quality': audio_quality,
            'video_quality': video_quality,
            'rtt': rtt,
            'packet_loss': packet_loss
        }, broadcast=True)
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': f'Quality metrics recording failed: {str(e)}'})

# Add this route for checking call status
@app.route('/api/call/status/<int:appointment_id>')
@login_required
def get_call_status(appointment_id):
    """Get current call status for an appointment"""
    call_info = active_calls.get(appointment_id, {})
    return jsonify(call_info)


@app.route('/api/call/resume/<int:appointment_id>')
@login_required
def resume_call_session(appointment_id):
    """Return resumable active call info for reconnect flows."""
    try:
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return jsonify({'success': False, 'error': 'appointment_not_found'}), 404
        if not verify_appointment_access(appointment, current_user):
            return jsonify({'success': False, 'error': 'access_denied'}), 403

        _, info = find_active_call(appointment_id=appointment_id)
        if not info:
            return jsonify({'success': True, 'resumable': False, 'call': None})

        participants = {
            int(info.get('caller') or info.get('caller_id') or -1),
            int(info.get('callee') or info.get('callee_id') or -1)
        }
        if int(current_user.id) not in participants:
            return jsonify({'success': False, 'error': 'access_denied'}), 403

        return jsonify({
            'success': True,
            'resumable': info.get('status') in ('ringing', 'accepted', 'ongoing', 'connected'),
            'call': {
                'call_id': info.get('id') or info.get('call_id'),
                'appointment_id': info.get('appointment_id') or appointment_id,
                'status': info.get('status'),
                'call_type': info.get('call_type', 'video'),
                'caller_id': info.get('caller') or info.get('caller_id'),
                'callee_id': info.get('callee') or info.get('callee_id'),
                'accepted_at': info.get('accepted_at') or info.get('accepted_time'),
                'started_at': info.get('started_at') or info.get('start_time')
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/call/feedback', methods=['POST'])
@login_required
@csrf.exempt
def submit_call_feedback():
    """Capture post-call quality feedback and issue reports."""
    try:
        data = request.get_json() or {}
        appointment_id = data.get('appointment_id')
        call_id = data.get('call_id')
        rating = data.get('rating')
        issue = (data.get('issue') or '').strip()
        details = (data.get('details') or '').strip()

        if not appointment_id and not call_id:
            return jsonify({'success': False, 'error': 'appointment_id_or_call_id_required'}), 400

        appointment = None
        if appointment_id:
            appointment = db.session.get(Appointment, int(appointment_id))
            if not appointment:
                return jsonify({'success': False, 'error': 'appointment_not_found'}), 404
            if not verify_appointment_access(appointment, current_user):
                return jsonify({'success': False, 'error': 'access_denied'}), 403

        # Persist via AuditLog without schema migration risk
        payload = {
            'appointment_id': appointment_id,
            'call_id': call_id,
            'rating': rating,
            'issue': issue,
            'details': details
        }
        log = AuditLog(
            user_id=current_user.id,
            action='call_feedback',
            description=json.dumps(payload),
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/appointment/<int:appointment_id>/realtime-bootstrap', methods=['GET'])
@login_required
def appointment_realtime_bootstrap(appointment_id):
    """Return realtime bootstrap payload for reconnect/offline recovery flows."""
    try:
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return jsonify({'success': False, 'error': 'appointment_not_found'}), 404
        if not verify_appointment_access(appointment, current_user):
            return jsonify({'success': False, 'error': 'access_denied'}), 403

        can_message, reason = True, 'ok'
        if current_user.role == 'patient':
            if not is_consultation_paid(appointment_id):
                can_message, reason = False, 'payment_required'

        unread_count = Communication.query.filter(
            Communication.appointment_id == appointment_id,
            Communication.sender_id != current_user.id,
            Communication.is_read == False
        ).count()

        _, active = find_active_call(appointment_id=appointment_id)
        payload = {
            'appointment_id': appointment_id,
            'unread_count': unread_count,
            'can_message': bool(can_message),
            'reason': reason,
            'payment_status': getattr(appointment, 'payment_status', None),
            'active_call': None
        }

        if active:
            payload['active_call'] = _serialize_active_call(active)
            if payload['active_call']:
                payload['active_call']['accepted_at'] = active.get('accepted_at') or active.get('accepted_time')

        return jsonify({'success': True, 'data': payload})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this route for getting missed calls
@app.route('/api/missed_calls')
@login_required
def get_missed_calls():
    """Get missed calls for current user"""
    # This would typically query a database table for missed calls
    # For now, return empty array - implementation would depend on your data model
    return jsonify([])


@app.route('/api/presence/online-users', methods=['GET'])
@login_required
def api_presence_online_users():
    """Compatibility endpoint for admin dashboard online user presence."""
    try:
        if current_user.role != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        online_list = []
        for user_id, sockets in user_sockets.items():
            try:
                sid_list = _normalize_sid_list(sockets)
                if not sid_list:
                    continue
                user = db.session.get(User, int(user_id))
                if not user:
                    continue
                online_list.append({
                    'user_id': user.id,
                    'name': safe_display_name(user),
                    'role': user.role,
                    'status': 'online',
                    'last_seen': user_last_seen.get(user.id).isoformat() if hasattr(user_last_seen.get(user.id), 'isoformat') else user_last_seen.get(user.id)
                })
            except Exception:
                continue

        return jsonify({'success': True, 'data': online_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/calls/quality-metrics', methods=['GET'])
@login_required
def api_calls_quality_metrics_list():
    """Compatibility endpoint for admin quality metrics table."""
    try:
        if current_user.role != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        limit = request.args.get('limit', 50, type=int)
        min_packet_loss = request.args.get('min_packet_loss', type=float)

        q = CallQualityMetrics.query.order_by(CallQualityMetrics.timestamp.desc())
        if min_packet_loss is not None:
            q = q.filter(CallQualityMetrics.packet_loss >= min_packet_loss)

        rows = q.limit(max(1, min(limit, 500))).all()
        out = []
        for row in rows:
            try:
                payload = row.to_dict()
                payload.update({
                    'call_id': row.call_id,
                    'user_id': row.user_id,
                    'audio_quality': row.audio_quality,
                    'video_quality': row.video_quality,
                    'video_resolution': row.video_resolution,
                    'video_framerate': row.video_framerate,
                    'available_bandwidth': row.available_bandwidth,
                    'memory_usage': row.memory_usage
                })
                out.append(payload)
            except Exception:
                continue

        return jsonify({'success': True, 'data': out})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/metrics/communication', methods=['GET'])
@login_required
def api_communication_metrics():
    """Operational communication metrics for admin monitoring dashboards."""
    try:
        if current_user.role != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        def _metric_get(name, default=0):
            try:
                client = _get_redis_client()
                if client:
                    value = client.get(f"metrics:{name}")
                    if value is not None:
                        return int(float(value))
            except Exception:
                pass
            return int(metrics_cache.get(name, default) or default)

        total_msg_latency = _metric_get('message_latency_ms_total', 0)
        total_msg_count = _metric_get('message_latency_count', 0)
        total_chat_latency = _metric_get('chat_message_latency_ms_total', 0)
        total_chat_count = _metric_get('chat_message_latency_count', 0)

        total_latency = total_msg_latency + total_chat_latency
        total_count = total_msg_count + total_chat_count
        avg_latency_ms = int(total_latency / total_count) if total_count > 0 else 0

        payload = {
            'online_users': _count_online_users(),
            'messages': {
                'avg_latency_ms': avg_latency_ms,
                'samples': total_count
            },
            'calls': {
                'video_initiated': _metric_get('calls_video_initiated', 0),
                'video_accepted': _metric_get('calls_video_accepted', 0),
                'video_ended': _metric_get('calls_video_ended', 0),
                'video_busy': _metric_get('calls_video_busy', 0),
                'video_missed': _metric_get('calls_video_missed', 0),
                'video_rejected': _metric_get('calls_video_rejected', 0),
                'voice_initiated': _metric_get('calls_voice_initiated', 0),
                'voice_accepted': _metric_get('calls_voice_accepted', 0),
                'voice_ended': _metric_get('calls_voice_ended', 0),
                'voice_busy': _metric_get('calls_voice_busy', 0),
                'voice_missed': _metric_get('calls_voice_missed', 0),
                'voice_rejected': _metric_get('calls_voice_rejected', 0),
                'payment_blocked': _metric_get('calls_payment_blocked', 0)
            },
            'socket': {
                'connections': _metric_get('connections', 0)
            }
        }
        return jsonify({'success': True, 'data': payload})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/communication/overview', methods=['GET'])
@login_required
def api_admin_communication_overview():
    try:
        if current_user.role != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        start_date_raw = (request.args.get('start_date') or '').strip()
        end_date_raw = (request.args.get('end_date') or '').strip()

        start_dt = None
        end_dt = None

        if start_date_raw:
            try:
                parsed = date.fromisoformat(start_date_raw)
                start_dt = datetime(parsed.year, parsed.month, parsed.day, 0, 0, 0, tzinfo=EAT_TZ)
            except Exception:
                return jsonify({'success': False, 'error': 'Invalid start_date'}), 400

        if end_date_raw:
            try:
                parsed = date.fromisoformat(end_date_raw)
                end_dt = datetime(parsed.year, parsed.month, parsed.day, 23, 59, 59, 999999, tzinfo=EAT_TZ)
            except Exception:
                return jsonify({'success': False, 'error': 'Invalid end_date'}), 400

        if start_dt and end_dt and start_dt > end_dt:
            return jsonify({'success': False, 'error': 'start_date must be before end_date'}), 400

        active_payload = []
        for value in list(active_calls.values()):
            if not isinstance(value, dict):
                continue
            call_id = value.get('id') or value.get('call_id')
            if any(item.get('call_id') == call_id for item in active_payload):
                continue
            started_at = value.get('started_at') or value.get('ringing_at')
            duration_seconds = None
            started_at_dt = None
            try:
                if started_at:
                    started_at_dt = datetime.fromisoformat(started_at)
                    duration_seconds = int((now_eat() - started_at_dt).total_seconds())
            except Exception:
                duration_seconds = None
                started_at_dt = None

            if start_dt and started_at_dt and started_at_dt < start_dt:
                continue
            if end_dt and started_at_dt and started_at_dt > end_dt:
                continue

            serialized = _serialize_active_call(value) or {}
            serialized['started_at'] = started_at
            serialized['duration_seconds'] = duration_seconds
            active_payload.append(serialized)

        recent_history_query = CallHistory.query
        if start_dt:
            recent_history_query = recent_history_query.filter(CallHistory.initiated_at >= start_dt)
        if end_dt:
            recent_history_query = recent_history_query.filter(CallHistory.initiated_at <= end_dt)
        recent_history = recent_history_query.order_by(CallHistory.initiated_at.desc()).limit(250).all()

        recent_quality_query = CallQualityMetrics.query
        if start_dt:
            recent_quality_query = recent_quality_query.filter(CallQualityMetrics.timestamp >= start_dt)
        if end_dt:
            recent_quality_query = recent_quality_query.filter(CallQualityMetrics.timestamp <= end_dt)
        recent_quality = recent_quality_query.order_by(CallQualityMetrics.timestamp.desc()).limit(250).all()

        blocked_query = Appointment.query.filter(
            Appointment.payment_status == 'unpaid',
            Appointment.status.in_(['pending', 'confirmed', 'scheduled'])
        )
        if start_dt:
            blocked_query = blocked_query.filter(Appointment.appointment_date >= start_dt)
        if end_dt:
            blocked_query = blocked_query.filter(Appointment.appointment_date <= end_dt)
        blocked_count = blocked_query.count()

        missed_by_doctor = {}
        failed_by_patient = {}
        quality_problem_count = 0

        for row in recent_history:
            reason = (row.end_reason or '').lower()
            if reason in ('unanswered', 'missed', 'timeout', 'declined', 'callee_declined', 'rejected', 'user_declined'):
                missed_by_doctor[row.caller_id] = missed_by_doctor.get(row.caller_id, 0) + 1
            if reason in ('connection_failed', 'failed_network', 'network_error'):
                failed_by_patient[row.callee_id] = failed_by_patient.get(row.callee_id, 0) + 1

        for metric in recent_quality:
            if (metric.packet_loss or 0) >= 0.08 or (metric.rtt or 0) >= 400 or (metric.video_quality or '').lower() in ('fair', 'poor'):
                quality_problem_count += 1

        def _rank_users(counter):
            ranked = []
            for user_id, count in sorted(counter.items(), key=lambda item: item[1], reverse=True)[:5]:
                user = db.session.get(User, user_id) if user_id else None
                ranked.append({
                    'user_id': user_id,
                    'name': safe_display_name(user) if user else 'Unknown',
                    'count': count
                })
            return ranked

        return jsonify({
            'success': True,
            'data': {
                'active_users': _count_online_users(),
                'active_calls': active_payload,
                'payment_blocked_consultations': blocked_count,
                'quality_problem_samples': quality_problem_count,
                'doctor_missed_rankings': _rank_users(missed_by_doctor),
                'patient_connection_rankings': _rank_users(failed_by_patient),
                'window': {
                    'start_date': start_date_raw or None,
                    'end_date': end_date_raw or None
                }
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/communication/messages/<int:appointment_id>', methods=['GET'])
@login_required
def api_admin_consultation_messages(appointment_id):
    try:
        if getattr(current_user, 'role', None) != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return jsonify({'success': False, 'error': 'appointment_not_found'}), 404

        messages = _serialize_admin_message_thread(appointment_id)
        return jsonify({'success': True, 'messages': messages, 'count': len(messages)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/communication/live-consultations', methods=['GET'])
@login_required
def api_admin_live_consultations():
    try:
        if getattr(current_user, 'role', None) != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        live_items = []
        dedupe_ids = set()
        active_values = list(active_calls.values())
        for call in active_values:
            if not isinstance(call, dict):
                continue
            call_id = call.get('id') or call.get('call_id')
            if call_id in dedupe_ids:
                continue
            dedupe_ids.add(call_id)

            call_type = (call.get('call_type') or 'video').strip().lower()
            call_status = (call.get('status') or '').strip().lower()
            if call_type != 'video':
                continue
            if call_status not in ('ringing', 'accepted', 'connecting', 'connected', 'ongoing'):
                continue

            appointment_id = call.get('appointment_id')
            appointment = db.session.get(Appointment, int(appointment_id)) if appointment_id else None
            patient_name = call.get('callee_name') or 'Patient'
            doctor_name = call.get('caller_name') or 'Doctor'
            reason = 'General consultation'
            scheduled_at = None
            if appointment:
                try:
                    patient_name = safe_display_name(appointment.patient.user) if appointment.patient and appointment.patient.user else patient_name
                except Exception:
                    pass
                try:
                    doctor_name = safe_display_name(appointment.doctor.user) if appointment.doctor and appointment.doctor.user else doctor_name
                except Exception:
                    pass
                reason = appointment.symptoms or appointment.notes or reason
                scheduled_at = appointment.appointment_date.isoformat() if appointment.appointment_date else None

            serialized = _serialize_active_call(call) or {}
            monitor_url = serialized.get('observe_url')
            if not monitor_url and appointment_id:
                try:
                    monitor_url = url_for('video_call', appointment_id=appointment_id, observer='1')
                except Exception:
                    monitor_url = None

            live_items.append({
                'call_id': call_id,
                'appointment_id': appointment_id,
                'status': call_status,
                'patient_name': patient_name,
                'doctor_name': doctor_name,
                'reason': reason,
                'scheduled_at': scheduled_at,
                'started_at': call.get('started_at') or call.get('ringing_at'),
                'monitor_url': monitor_url,
                'participants_count': call.get('participants_count') or len(_call_participant_ids(call, include_observers=False)),
            })

        recent_calls = CallHistory.query.order_by(CallHistory.initiated_at.desc()).limit(500).all()
        ended_count = sum(1 for row in recent_calls if (row.status or '').lower() == 'ended')
        missed_count = sum(1 for row in recent_calls if (row.end_reason or '').lower() in ('missed', 'timeout', 'unanswered', 'declined', 'callee_declined', 'rejected'))
        rescheduled_count = Appointment.query.filter(Appointment.status == 'rescheduled').count()
        summary = {
            'live': len(live_items),
            'ended': ended_count,
            'rescheduled': rescheduled_count,
            'missed': missed_count,
            'total': Appointment.query.count(),
        }

        return jsonify({'success': True, 'summary': summary, 'items': live_items})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/communication/recordings', methods=['GET'])
@login_required
def api_admin_consultation_recordings():
    try:
        if getattr(current_user, 'role', None) != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        rows = CallHistory.query.order_by(CallHistory.initiated_at.desc()).limit(500).all()
        recordings = []
        for row in rows:
            appointment = db.session.get(Appointment, row.appointment_id) if row.appointment_id else None
            patient_name = 'Unknown Patient'
            doctor_name = 'Unknown Doctor'
            reason = 'General consultation'
            scheduled_at = None
            if appointment:
                try:
                    patient_name = safe_display_name(appointment.patient.user) if appointment.patient and appointment.patient.user else patient_name
                except Exception:
                    pass
                try:
                    doctor_name = safe_display_name(appointment.doctor.user) if appointment.doctor and appointment.doctor.user else doctor_name
                except Exception:
                    pass
                reason = appointment.symptoms or appointment.notes or reason
                scheduled_at = appointment.appointment_date.isoformat() if appointment.appointment_date else None

            recordings.append({
                'call_id': row.call_id,
                'appointment_id': row.appointment_id,
                'patient_name': patient_name,
                'doctor_name': doctor_name,
                'reason': reason,
                'scheduled_at': scheduled_at,
                'call_type': row.call_type,
                'status': row.status,
                'end_reason': row.end_reason,
                'recording_url': row.recording_url,
                'recording_duration': row.recording_duration,
                'recording_size': row.recording_size,
                'recorded_at': row.ended_at.isoformat() if row.ended_at else (row.initiated_at.isoformat() if row.initiated_at else None),
            })

        return jsonify({'success': True, 'recordings': recordings})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/ops/dispatch-day-reminders', methods=['POST'])
@login_required
@csrf.exempt
def api_admin_dispatch_day_reminders():
    try:
        if getattr(current_user, 'role', None) != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        payload = request.get_json(silent=True) or request.form or {}
        date_raw = (payload.get('date') or '').strip()
        dry_run = parse_bool_flag(payload.get('dry_run'), default=False)

        target_date = None
        if date_raw:
            try:
                target_date = date.fromisoformat(date_raw)
            except Exception:
                return jsonify({'success': False, 'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
        else:
            target_date = now_eat().date()

        stats = dispatch_day_of_appointment_reminders(target_date=target_date, dry_run=dry_run)
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/patient-region-stats', methods=['GET'])
@login_required
def api_admin_patient_region_stats():
    try:
        if getattr(current_user, 'role', None) != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        rows = db.session.query(Patient, User).join(User, Patient.user_id == User.id).all()
        region_counts = {}
        with_location = 0
        for patient_row, user_row in rows:
            region_value = (patient_row.city or patient_row.country or '').strip()
            if not region_value:
                region_value = (patient_row.address or '').strip()
            if not region_value and getattr(user_row, 'last_known_timezone', None):
                region_value = user_row.last_known_timezone
            if not region_value:
                region_value = 'Unknown'
            region_counts[region_value] = region_counts.get(region_value, 0) + 1
            if region_value != 'Unknown':
                with_location += 1

        sorted_regions = sorted(region_counts.items(), key=lambda item: item[1], reverse=True)
        return jsonify({
            'success': True,
            'data': {
                'regions': [{'region': key, 'count': count} for key, count in sorted_regions],
                'total_patients': len(rows),
                'with_location': with_location,
                'without_location': max(0, len(rows) - with_location)
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/partners', methods=['GET', 'POST'])
@login_required
def api_admin_partners():
    try:
        if getattr(current_user, 'role', None) != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        if request.method == 'GET':
            rows = Partner.query.order_by(Partner.partner_type.asc(), Partner.name.asc()).all()
            return jsonify({'success': True, 'partners': [row.to_dict() for row in rows]})

        payload = request.get_json(silent=True) or request.form or {}
        name = (payload.get('name') or '').strip()
        partner_type = (payload.get('partner_type') or '').strip().lower()
        if partner_type in ('pharmacises', 'pharmacies'):
            partner_type = 'pharmacy'
        if partner_type in ('hospitals',):
            partner_type = 'hospital'
        if partner_type in ('labs', 'laboratory'):
            partner_type = 'lab'

        if not name:
            return jsonify({'success': False, 'error': 'name_required'}), 400
        if partner_type not in ('hospital', 'lab', 'pharmacy'):
            return jsonify({'success': False, 'error': 'partner_type_invalid'}), 400

        partner = Partner(
            name=name,
            partner_type=partner_type,
            region=(payload.get('region') or '').strip() or None,
            city=(payload.get('city') or '').strip() or None,
            country=(payload.get('country') or '').strip() or None,
            contact_email=(payload.get('contact_email') or '').strip() or None,
            contact_phone=(payload.get('contact_phone') or '').strip() or None,
            website=(payload.get('website') or '').strip() or None,
            notes=(payload.get('notes') or '').strip() or None,
            is_active=parse_bool_flag(payload.get('is_active'), default=True),
        )
        db.session.add(partner)
        db.session.commit()
        return jsonify({'success': True, 'partner': partner.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@socketio.on('call_chat_message')
def handle_call_chat_message(data):
    """Handle chat messages during call"""
    if not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'call_chat_message', 60, 60):
        emit('call_error', {'error': 'rate_limited'})
        return
    
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    appointment = _socket_get_appointment(appointment_id, error_event='call_error', require_payment=True)
    if not appointment:
        return
    
    # Broadcast chat message to all in the call
    _, call_info = find_active_call(appointment_id=appointment_id)
    room_name = (call_info or {}).get('room_id') or f'voice_call_{appointment_id}'
    emit('call_chat_message', {
        'appointment_id': appointment_id,
        'message': data.get('message'),
        'sender_id': current_user.id,
        'sender_name': safe_display_name(current_user),
        'timestamp': now_eat().isoformat()
    }, room=room_name)
    _log_event('call_chat_message', user_id=current_user.id, appointment_id=appointment_id)

@socketio.on('call_file_share')
def handle_call_file_share(data):
    """Handle file sharing during call"""
    if not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'call_file_share', 10, 60):
        emit('call_error', {'error': 'rate_limited'})
        return
    
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    appointment = _socket_get_appointment(appointment_id, error_event='call_error', require_payment=True)
    if not appointment:
        return
    client_file_id = data.get('client_file_id') if isinstance(data, dict) else None
    if client_file_id:
        cache_key = f'call_file:{client_file_id}'
        if _idempotency_get(current_user.id, cache_key):
            return
    
    # Broadcast file share to all in the call
    _, call_info = find_active_call(appointment_id=appointment_id)
    room_name = (call_info or {}).get('room_id') or f'voice_call_{appointment_id}'
    emit('call_file_share', {
        'appointment_id': appointment_id,
        'file_name': data.get('file_name'),
        'file_data': data.get('file_data'),
        'file_size': data.get('file_size'),
        'client_file_id': client_file_id,
        'sender_id': current_user.id,
        'sender_name': safe_display_name(current_user),
        'timestamp': now_eat().isoformat()
    }, room=room_name, skip_sid=request.sid)
    if client_file_id:
        _idempotency_set(current_user.id, f'call_file:{client_file_id}', {'status': 'ok'})
    _log_event('call_file_share', user_id=current_user.id, appointment_id=appointment_id)

@socketio.on('call_user_info')
def handle_call_user_info(data):
    """Handle user profile info during call"""
    if not current_user.is_authenticated:
        return
    if not _rate_limit(current_user.id, 'call_user_info', 30, 60):
        emit('call_error', {'error': 'rate_limited'})
        return
    
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    appointment = _socket_get_appointment(appointment_id, error_event='call_error', require_payment=True)
    if not appointment:
        return
    call_id = data.get('call_id') if isinstance(data, dict) else None
    target_user_id = data.get('target_user_id') if isinstance(data, dict) else None
    call_type = _resolve_call_type(call_id=call_id, appointment_id=appointment_id, data=data)
    
    payload = {
        'appointment_id': appointment_id,
        'call_id': call_id,
        'user_id': current_user.id,
        'first_name': data.get('first_name'),
        'last_name': data.get('last_name'),
        'profile_picture_url': data.get('profile_picture_url'),
        'display_name': safe_display_name(current_user),
        'target_user_id': target_user_id,
        'timestamp': now_eat().isoformat()
    }
    _emit_call_signal(
        'call_user_info',
        payload,
        appointment_id=appointment_id,
        call_id=call_id,
        call_type=call_type,
        target_user_id=target_user_id,
    )
    _log_event('call_user_info', user_id=current_user.id, appointment_id=appointment_id)


# ============================================================================
# NEW VOICE CALL SYSTEM — Socket.IO Handlers
# ============================================================================

@socketio.on('initiate_voice_call')
def handle_initiate_voice_call(data):
    """Initiate a voice call between two appointment participants."""
    if not current_user or not current_user.is_authenticated:
        emit('call_error', {'error': 'not_authenticated'})
        return {'success': False, 'error': 'not_authenticated'}
    if not _rate_limit(current_user.id, 'initiate_voice_call', 6, 60):
        emit('call_error', {'error': 'rate_limited'})
        return {'success': False, 'error': 'rate_limited'}

    try:
        appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
        appointment = _socket_get_appointment(appointment_id, error_event='call_error', require_payment=True)
        if not appointment:
            return {'success': False, 'error': 'appointment_not_found'}

        caller_id = int(current_user.id)
        caller_name = safe_display_name(current_user)
        caller_role = current_user.role
        requested_participant_ids = _unique_user_ids((data or {}).get('participant_ids') or [])
        requested_observer_ids = _unique_user_ids((data or {}).get('observer_ids') or [])

        if current_user.role == 'patient':
            callee_user_id = appointment.doctor.user_id
            callee_role = 'doctor'
        else:
            callee_user_id = appointment.patient.user_id
            callee_role = 'patient'

        callee_user = db.session.get(User, callee_user_id)
        callee_name = safe_display_name(callee_user) if callee_user else 'User'

        call_id = str(uuid4())
        participants = _build_call_participants(
            appointment, caller_id,
            callee_id=callee_user_id,
            participant_ids=requested_participant_ids,
            observer_ids=requested_observer_ids,
        )
        room_id = _get_call_room_name('voice', appointment_id=appointment_id, call_id=call_id)
        auto_record = (data or {}).get('auto_record', True) is not False

        # Callee busy check
        if _is_user_busy(callee_user_id):
            busy_payload = {
                'call_id': call_id, 'appointment_id': appointment_id,
                'status': 'busy', 'message': f'{callee_name} is currently on another call',
                'callee_name': callee_name,
            }
            _emit_to_user(caller_id, 'call_failed_busy', busy_payload)
            _record_call_history(
                call_id=call_id, appointment_id=appointment_id,
                caller_id=caller_id, callee_id=callee_user_id,
                call_type='voice', status='ended',
                ended_at=now_eat(), end_reason='busy',
                room_id=room_id, sfu_server=_get_call_sfu_server(),
                participants_count=len(_call_participant_ids({'participants': participants}, include_observers=False)),
                recording_consent=auto_record,
            )
            _metric_incr('calls_voice_busy', 1)
            try:
                db.session.add(Notification(
                    user_id=caller_id, appointment_id=appointment_id,
                    notification_type='busy_voice_call', sender_id=callee_user_id,
                    title='User Busy', body=f'{callee_name} is currently on another call',
                    call_status='busy'))
                db.session.commit()
            except Exception:
                db.session.rollback()
            return {'success': False, 'error': 'User is busy'}

        # Build call info
        call_info = {
            'id': call_id, 'call_id': call_id,
            'appointment_id': appointment_id,
            'caller': caller_id, 'caller_id': caller_id,
            'caller_name': caller_name, 'caller_role': caller_role,
            'callee': callee_user_id, 'callee_id': callee_user_id,
            'callee_name': callee_name, 'callee_role': callee_role,
            'call_type': 'voice',
            'started_at': now_eat().isoformat(),
            'ringing_at': now_eat().isoformat(),
            'status': 'ringing',
            'participants': participants,
            'participant_ids': _call_participant_ids({'participants': participants}, include_observers=False),
            'observer_ids': _unique_user_ids(requested_observer_ids),
            'connected_participant_ids': [caller_id],
            'participants_count': len(_call_participant_ids({'participants': participants}, include_observers=False)),
            'group_call': len(_call_participant_ids({'participants': participants}, include_observers=False)) > 2,
            'room_id': room_id,
            'media_topology': (data or {}).get('media_topology') or _get_call_media_topology(),
            'sfu_server': _get_call_sfu_server(),
            'auto_record': auto_record, 'recording_state': 'armed',
        }
        try:
            call_info['caller_profile_picture'] = get_user_profile_picture_url(current_user)
        except Exception:
            call_info['caller_profile_picture'] = None
        try:
            call_info['callee_profile_picture'] = get_user_profile_picture_url(callee_user) if callee_user else None
        except Exception:
            call_info['callee_profile_picture'] = None

        # Persist
        _store_active_call(call_info)
        _incoming_call_set(callee_user_id, call_info)
        _emit_call_lifecycle(call_info, 'initiate')
        _record_call_history(
            call_id=call_id, appointment_id=appointment_id,
            caller_id=caller_id, callee_id=callee_user_id,
            call_type='voice', status='ringing',
            initiated_at=now_eat(), ringing_at=now_eat(),
            room_id=room_id, sfu_server=_get_call_sfu_server(),
            participants_count=call_info['participants_count'],
            recording_consent=auto_record,
        )
        _update_call_session(
            call_id=call_id, appointment_id=appointment_id,
            caller_id=caller_id, callee_id=callee_user_id,
            call_type='voice', status='ringing',
            started_at=now_eat(), participants=participants,
        )
        _metric_incr('calls_voice_initiated', 1)
        _set_appointment_call_status(appointment_id, 'ringing', initiated_by=caller_id)

        ring_payload = {
            'call_id': call_id, 'appointment_id': appointment_id,
            'caller_id': caller_id, 'caller_name': caller_name,
            'caller_profile_pic': call_info.get('caller_profile_picture'),
            'caller_role': caller_role,
            'callee_id': callee_user_id, 'callee_name': callee_name,
            'callee_role': callee_role,
            'callee_profile_pic': call_info.get('callee_profile_picture'),
            'call_type': 'voice', 'timestamp': now_eat().isoformat(),
        }
        emit('call_ringing', {'appointment_id': appointment_id, 'call_type': 'voice', 'call_id': call_id})

        if _is_user_online(callee_user_id):
            _emit_to_user(callee_user_id, 'incoming_voice_call', ring_payload)
            _emit_call_lifecycle(call_info, 'ringing', extra=ring_payload)

            def _voice_ring_timeout():
                try:
                    with app.app_context():
                        db_call = CallHistory.query.filter_by(call_id=str(call_id)).first()
                        if db_call and db_call.status == 'ended':
                            return
                        _, current = find_active_call(call_id=call_id, appointment_id=appointment_id)
                        if current and current.get('status') == 'ringing':
                            current['status'] = 'unanswered'
                            _incoming_call_pop(callee_user_id)
                            _record_call_history(
                                call_id=current.get('id') or call_id,
                                appointment_id=appointment_id,
                                caller_id=current.get('caller') or caller_id,
                                callee_id=callee_user_id,
                                call_type='voice', status='ended',
                                ended_at=now_eat(), end_reason='unanswered',
                            )
                            _metric_incr('calls_voice_missed', 1)
                            _set_appointment_call_status(appointment_id, 'missed')
                            _emit_to_user(caller_id, 'voice_call_unanswered', {
                                'call_id': current.get('id') or call_id,
                                'appointment_id': appointment_id,
                                'message': f'{callee_name} did not answer',
                                'status': 'unanswered',
                            })
                            _emit_call_lifecycle(current, 'missed', extra={'reason': 'unanswered'})
                            _insert_call_event_message(appointment_id, caller_id, callee_user_id, 'voice', 'missed')
                            try:
                                db.session.add(Notification(
                                    user_id=callee_user_id, appointment_id=appointment_id,
                                    notification_type='missed_voice_call', sender_id=caller_id,
                                    title='Missed Voice Call', body=f'{caller_name} called you',
                                    call_status='missed'))
                                db.session.commit()
                            except Exception:
                                try: db.session.rollback()
                                except Exception: pass
                            _clear_active_call(current)
                except Exception:
                    pass

            socketio.start_background_task(
                lambda: (socketio.sleep(app.config.get('CALL_RING_TIMEOUT', 60)), _voice_ring_timeout()))
        else:
            _emit_to_user(caller_id, 'call_ringing', {
                'call_id': call_id, 'appointment_id': appointment_id,
                'status': 'offline_attempting',
                'message': f'{callee_name} is currently offline',
            })

            def _voice_offline_timeout():
                try:
                    with app.app_context():
                        db_call = CallHistory.query.filter_by(call_id=str(call_id)).first()
                        if db_call and db_call.status == 'ended':
                            return
                        _, current = find_active_call(call_id=call_id, appointment_id=appointment_id)
                        if current and current.get('status') == 'ringing':
                            current['status'] = 'connection_failed'
                            _incoming_call_pop(callee_user_id)
                            _record_call_history(
                                call_id=current.get('id') or call_id,
                                appointment_id=appointment_id,
                                caller_id=current.get('caller') or caller_id,
                                callee_id=callee_user_id,
                                call_type='voice', status='ended',
                                ended_at=now_eat(), end_reason='connection_failed',
                            )
                            _metric_incr('calls_voice_connection_failed', 1)
                            _set_appointment_call_status(appointment_id, 'missed')
                            _emit_to_user(caller_id, 'voice_call_connection_failed', {
                                'call_id': current.get('id') or call_id,
                                'appointment_id': appointment_id,
                                'message': f'Unable to connect to {callee_name}',
                                'status': 'connection_failed',
                            })
                            _emit_call_lifecycle(current, 'failed', extra={'reason': 'connection_failed'})
                            _insert_call_event_message(appointment_id, caller_id, callee_user_id, 'voice', 'connection_failed')
                            try:
                                db.session.add(Notification(
                                    user_id=caller_id, appointment_id=appointment_id,
                                    notification_type='voice_call_failed', sender_id=callee_user_id,
                                    title='Call Connection Failed', body=f'Unable to reach {callee_name}',
                                    call_status='connection_failed'))
                                db.session.commit()
                            except Exception:
                                try: db.session.rollback()
                                except Exception: pass
                            _clear_active_call(current)
                except Exception:
                    pass

            socketio.start_background_task(
                lambda: (socketio.sleep(app.config.get('CALL_OFFLINE_TIMEOUT', 90)), _voice_offline_timeout()))

        _log_event('voice_call_initiated', caller_id=caller_id, callee_id=callee_user_id, appointment_id=appointment_id)
        return {'success': True, 'call_id': call_id}
    except Exception as e:
        app.logger.exception('Error initiating voice call')
        emit('call_error', {'error': str(e)})
        return {'success': False, 'error': str(e)}


@socketio.on('accept_voice_call')
def handle_accept_voice_call(data):
    """Callee accepts an incoming voice call."""
    if not current_user or not current_user.is_authenticated:
        return {'success': False, 'error': 'not_authenticated'}

    try:
        call_id = data.get('call_id') if isinstance(data, dict) else None
        appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
        _, call = find_active_call(call_id=call_id, appointment_id=appointment_id)

        if not call:
            emit('call_error', {'error': 'call_not_found'})
            return {'success': False, 'error': 'No active voice call found'}

        if not _is_call_participant(call, current_user.id, include_observers=False) or \
           int(current_user.id) == int(call.get('caller') or call.get('caller_id')):
            emit('call_error', {'error': 'access_denied'})
            return {'success': False, 'error': 'Not authorized'}

        call['status'] = 'connected'
        call['accepted_at'] = now_eat().isoformat()
        call['connected_at'] = now_eat().isoformat()
        _mark_call_participant(call, current_user.id, status='connected', joined=True)
        _store_active_call(call)
        _incoming_call_pop(current_user.id)

        _record_call_history(
            call_id=call.get('id') or call.get('call_id'),
            appointment_id=appointment_id,
            caller_id=call.get('caller') or call.get('caller_id'),
            callee_id=current_user.id,
            call_type='voice', status='connected',
            accepted_at=now_eat(), connected_at=now_eat(),
            room_id=call.get('room_id'),
            sfu_server=call.get('sfu_server') or _get_call_sfu_server(),
            participants_count=call.get('participants_count'),
            recording_consent=call.get('auto_record', True),
        )
        try:
            session_row = _update_call_session(
                call_id=call.get('id') or call.get('call_id'),
                appointment_id=appointment_id,
                caller_id=call.get('caller') or call.get('caller_id'),
                callee_id=current_user.id,
                call_type='voice', status='ongoing',
                started_at=now_eat(), accepted_at=now_eat(),
                connected_at=now_eat(), participants=call.get('participants'),
            )
            if session_row:
                call['call_session_id'] = session_row.id
        except Exception:
            db.session.rollback()

        _metric_incr('calls_voice_accepted', 1)
        _set_appointment_call_status(appointment_id, 'ongoing')

        accept_payload = {
            'call_id': call.get('id') or call.get('call_id'),
            'appointment_id': appointment_id,
            'callee_name': safe_display_name(current_user),
            'call_type': 'voice',
        }
        caller_id = call.get('caller') or call.get('caller_id')
        _emit_to_user(caller_id, 'voice_call_accepted', accept_payload)
        emit('call_connected', {
            'call_id': call.get('id') or call.get('call_id'),
            'appointment_id': appointment_id, 'call_type': 'voice',
        })
        _emit_call_lifecycle(call, 'accept', extra=accept_payload)
        _emit_call_lifecycle(call, 'connected', extra=accept_payload)

        _log_event('voice_call_accepted', caller_id=caller_id, callee_id=current_user.id, appointment_id=appointment_id)
        return {'success': True}
    except Exception as e:
        app.logger.exception('Error accepting voice call')
        emit('call_error', {'error': str(e)})
        return {'success': False, 'error': str(e)}


@socketio.on('reject_voice_call')
def handle_reject_voice_call(data):
    """Callee declines a voice call."""
    payload = dict(data or {})
    payload.setdefault('reason', 'rejected')
    return handle_end_voice_call(payload)


@socketio.on('end_voice_call')
def handle_end_voice_call(data):
    """End an active voice call for any reason."""
    if not current_user or not current_user.is_authenticated:
        return {'success': False, 'error': 'not_authenticated'}

    try:
        call_id = data.get('call_id') if isinstance(data, dict) else None
        appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
        reason = (data.get('reason') if isinstance(data, dict) else None) or 'completed'
        key, call = find_active_call(call_id=call_id, appointment_id=appointment_id)

        if not call:
            return {'success': False, 'error': 'No active call found'}

        caller_id = call.get('caller') or call.get('caller_id')
        callee_id = call.get('callee') or call.get('callee_id')
        if not _is_call_participant(call, current_user.id, include_observers=False) \
                and caller_id != current_user.id and callee_id != current_user.id:
            return {'success': False, 'error': 'Not authorized'}

        call['status'] = 'ended'
        call['ended_at'] = now_eat().isoformat()
        if key is not None:
            try: del active_calls[key]
            except Exception: pass
        _incoming_call_pop(callee_id)

        duration = 0
        started_at = call.get('connected_at') or call.get('accepted_at') or call.get('started_at')
        if started_at:
            try:
                duration = max(0, int((now_eat() - datetime.fromisoformat(started_at)).total_seconds()))
            except Exception:
                pass

        _record_call_history(
            call_id=call.get('id') or call.get('call_id'),
            appointment_id=appointment_id,
            caller_id=caller_id, callee_id=callee_id,
            call_type='voice', status='ended',
            ended_at=now_eat(), duration=duration, end_reason=reason,
        )

        session_status = 'completed' if reason == 'completed' else 'ended'
        _update_call_session(
            call_id=call.get('id') or call.get('call_id'),
            appointment_id=appointment_id,
            caller_id=caller_id, callee_id=callee_id,
            call_type='voice', status=session_status,
            ended_at=now_eat(), duration_seconds=duration, end_reason=reason,
        )

        cs_id = call.get('call_session_id')
        if cs_id:
            try:
                cs = db.session.get(CallSession, cs_id)
                if cs and not cs.ended_at:
                    cs.ended_at = now_eat()
                    cs.duration = duration
                    db.session.commit()
            except Exception:
                db.session.rollback()

        if reason == 'completed':
            _metric_incr('calls_voice_completed', 1)
            _set_appointment_call_status(appointment_id, 'completed')
        elif reason in ('rejected', 'declined', 'callee_declined', 'user_declined'):
            _metric_incr('calls_voice_rejected', 1)
            _set_appointment_call_status(appointment_id, 'missed')
        elif reason in ('unanswered', 'missed'):
            _metric_incr('calls_voice_missed', 1)
            _set_appointment_call_status(appointment_id, 'missed')
        else:
            _metric_incr('calls_voice_ended', 1)
            _set_appointment_call_status(appointment_id, 'ended')

        # Update appointment completion when doctor ends normally
        try:
            if appointment_id and reason == 'completed':
                apt = db.session.get(Appointment, appointment_id)
                if apt:
                    doctor_user_id = getattr(apt.doctor, 'user_id', None) if apt.doctor else None
                    if doctor_user_id and int(current_user.id) == int(doctor_user_id):
                        apt.status = 'completed'
                        db.session.commit()
                        try:
                            _emit_to_user(apt.patient.user_id, 'prompt_testimonial', {
                                'appointment_id': apt.id, 'doctor_id': apt.doctor_id})
                        except Exception:
                            pass
        except Exception:
            db.session.rollback()

        other_user_id = callee_id if caller_id == current_user.id else caller_id
        end_payload = {
            'call_id': call.get('id') or call.get('call_id'),
            'appointment_id': appointment_id,
            'ended_by': current_user.id,
            'duration': duration,
            'call_type': 'voice', 'reason': reason,
        }
        _emit_to_user(other_user_id, 'voice_call_ended', end_payload)
        emit('call_ended', end_payload)

        lifecycle = 'ended'
        if reason in ('rejected', 'declined', 'callee_declined', 'user_declined'):
            lifecycle = 'reject'
        elif reason in ('unanswered', 'missed'):
            lifecycle = 'missed'
        elif reason in ('connection_failed', 'failed_network', 'network_error'):
            lifecycle = 'failed'
        _emit_call_lifecycle(call, lifecycle, extra=end_payload)

        event_type = 'completed' if reason == 'completed' else \
            ('declined' if reason in ('rejected', 'declined', 'callee_declined', 'user_declined') else \
             ('missed' if reason in ('unanswered', 'missed') else reason))
        _insert_call_event_message(appointment_id, caller_id, callee_id, 'voice', event_type,
                                   duration=duration if duration > 0 else None)

        _log_event('voice_call_ended', appointment_id=appointment_id, duration=duration, reason=reason)
        return {'success': True, 'duration': duration}
    except Exception as e:
        app.logger.exception('Error ending voice call')
        emit('call_error', {'error': str(e)})
        return {'success': False, 'error': str(e)}


@socketio.on('join_voice_room')
def handle_join_voice_room(data):
    """Join a voice call's Socket.IO room for WebRTC signaling."""
    if not current_user or not current_user.is_authenticated:
        return
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    require_payment = getattr(current_user, 'role', None) != 'admin'
    appointment = _socket_get_appointment(appointment_id, error_event='error', require_payment=require_payment)
    if not appointment:
        return
    _, call_info = find_active_call(appointment_id=appointment_id)
    room_name = (call_info or {}).get('room_id') or _get_call_room_name('voice', appointment_id=appointment_id)
    observer_mode = bool((data or {}).get('observer_mode')) or getattr(current_user, 'role', None) == 'admin'
    if not observer_mode and call_info and not _is_call_participant(call_info, current_user.id, include_observers=False):
        emit('error', {'message': 'access_denied'})
        return
    join_room(room_name)
    room_size = _room_member_add(room_name, current_user.id)
    if call_info:
        _mark_call_participant(call_info, current_user.id, status='connected', joined=True,
                               mode='observer' if observer_mode else None)
        _store_active_call(call_info)
    emit('voice_room_snapshot', {
        'appointment_id': appointment_id, 'room_id': room_name,
        'observer_mode': observer_mode,
        'call': _serialize_active_call(call_info) if call_info else None,
    })
    if not observer_mode:
        emit('user_joined_voice_room', {
            'user_id': current_user.id,
            'user_name': safe_display_name(current_user),
            'appointment_id': appointment_id,
            'participants': (call_info or {}).get('participants') or [],
        }, room=room_name, skip_sid=request.sid)
    _log_event('join_voice_room', user_id=current_user.id, appointment_id=appointment_id, room_size=room_size)


@socketio.on('leave_voice_room')
def handle_leave_voice_room(data):
    """Leave a voice call's Socket.IO room."""
    if not current_user or not current_user.is_authenticated:
        return
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    require_payment = getattr(current_user, 'role', None) != 'admin'
    appointment = _socket_get_appointment(appointment_id, error_event='error', require_payment=require_payment)
    if not appointment:
        return
    _, call_info = find_active_call(appointment_id=appointment_id)
    room_name = (call_info or {}).get('room_id') or _get_call_room_name('voice', appointment_id=appointment_id)
    observer_mode = bool((data or {}).get('observer_mode')) or getattr(current_user, 'role', None) == 'admin'
    leave_room(room_name)
    room_size = _room_member_remove(room_name, current_user.id)
    if call_info:
        _mark_call_participant(call_info, current_user.id, status='left', joined=False,
                               mode='observer' if observer_mode else None)
        _store_active_call(call_info)
    if not observer_mode:
        emit('user_left_voice_room', {
            'user_id': current_user.id, 'appointment_id': appointment_id,
            'participants': (call_info or {}).get('participants') or [],
        }, room=room_name, skip_sid=request.sid)
    _log_event('leave_voice_room', user_id=current_user.id, appointment_id=appointment_id, room_size=room_size)


@socketio.on('voice:mute')
def handle_voice_mute(data):
    """Broadcast mute/unmute state to the call room."""
    if not current_user or not current_user.is_authenticated:
        return
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    muted = bool(data.get('muted')) if isinstance(data, dict) else True
    _, call_info = find_active_call(appointment_id=appointment_id)
    if not call_info:
        return
    room_name = call_info.get('room_id') or f'voice_call_{appointment_id}'
    emit('voice:mute_changed', {
        'user_id': current_user.id, 'user_name': safe_display_name(current_user),
        'muted': muted, 'appointment_id': appointment_id,
    }, room=room_name)


@socketio.on('voice:speaker')
def handle_voice_speaker(data):
    """Broadcast speaker toggle to the call room."""
    if not current_user or not current_user.is_authenticated:
        return
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    speaker_on = bool(data.get('speaker_on')) if isinstance(data, dict) else True
    _, call_info = find_active_call(appointment_id=appointment_id)
    if not call_info:
        return
    room_name = call_info.get('room_id') or f'voice_call_{appointment_id}'
    emit('voice:speaker_changed', {
        'user_id': current_user.id, 'speaker_on': speaker_on,
        'appointment_id': appointment_id,
    }, room=room_name)


@socketio.on('voice:hold')
def handle_voice_hold(data):
    """Toggle call hold."""
    if not current_user or not current_user.is_authenticated:
        return
    appointment_id = data.get('appointment_id') if isinstance(data, dict) else None
    on_hold = bool(data.get('on_hold')) if isinstance(data, dict) else True
    _, call_info = find_active_call(appointment_id=appointment_id)
    if not call_info:
        return
    room_name = call_info.get('room_id') or f'voice_call_{appointment_id}'
    emit('voice:hold_changed', {
        'user_id': current_user.id, 'user_name': safe_display_name(current_user),
        'on_hold': on_hold, 'appointment_id': appointment_id,
    }, room=room_name)


# ============================================
# ROOM MANAGEMENT
# ============================================

# -----------------------------------------------------------------
# CONSULTATION ROOM SOCKET.IO HANDLERS
# -----------------------------------------------------------------

@socketio.on('join_consultation_room')
def handle_join_consultation_room(data):
    """
    Client emits this when entering the consultation room page.
    Validates access, joins the secret Socket.IO room, and broadcasts presence.
    Data: { appointment_id, observer: bool (optional, admin only) }
    """
    if not current_user.is_authenticated:
        emit('consultation_room_error', {'error': 'unauthenticated'})
        return

    try:
        appointment_id = int(data.get('appointment_id', 0))
        is_observer = bool(data.get('observer', False)) and current_user.role == 'admin'
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            emit('consultation_room_error', {'error': 'appointment_not_found'})
            return

        allowed, reason = _check_room_access(appointment, current_user)
        if reason in ('not_your_appointment', 'unauthorized_role'):
            emit('consultation_room_error', {'error': reason})
            return

        room, _ = _get_or_create_consultation_room(appointment)

        # Join the secret socket room (token never sent to client)
        room_socket_name = f'consultation:{room.room_token}'
        join_room(room_socket_name)

        # Track membership
        if room_socket_name not in room_memberships:
            room_memberships[room_socket_name] = {}

        member_info = {
            'user_id': current_user.id,
            'display_name': safe_display_name(current_user),
            'role': current_user.role,
            'profile_picture': get_user_profile_picture_url(current_user),
            'joined_at': now_eat().isoformat(),
            'observer': is_observer,
        }
        room_memberships[room_socket_name][current_user.id] = member_info

        # Mark room active on first non-observer join
        if room.status == 'waiting' and not is_observer:
            room.status = 'active'
            room.started_at = now_eat()
            db.session.add(room)
            db.session.commit()

        # Filter observers out of the participant list sent to non-admin users
        all_participants = list(room_memberships[room_socket_name].values())
        visible_participants = [p for p in all_participants if not p.get('observer')]

        # Tell the joining client about the full room state
        emit('consultation_room_joined', {
            'appointment_id': appointment_id,
            'room': room.to_public_dict(),
            'participants': all_participants if is_observer else visible_participants,
            'observer': is_observer,
        })

        # Notify everyone else in the room — but NOT if observer (silent join)
        if not is_observer:
            emit('participant_joined', {
                'appointment_id': appointment_id,
                'participant': member_info,
                'participants': visible_participants,
            }, room=room_socket_name, include_self=False)

    except Exception as e:
        app.logger.error(f'join_consultation_room error: {e}')
        emit('consultation_room_error', {'error': str(e)})


@socketio.on('leave_consultation_room')
def handle_leave_consultation_room(data):
    """
    Client emits when leaving (tab close, end button, navigation away).
    Data: { appointment_id }
    """
    if not current_user.is_authenticated:
        return

    try:
        appointment_id = int(data.get('appointment_id', 0))
        room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
        if not room:
            return

        room_socket_name = f'consultation:{room.room_token}'
        leave_room(room_socket_name)

        if room_socket_name in room_memberships:
            room_memberships[room_socket_name].pop(current_user.id, None)

        participants = list((room_memberships.get(room_socket_name) or {}).values())

        emit('participant_left', {
            'appointment_id': appointment_id,
            'user_id': current_user.id,
            'display_name': safe_display_name(current_user),
            'participants': participants,
        }, room=room_socket_name)

    except Exception as e:
        app.logger.error(f'leave_consultation_room error: {e}')


@socketio.on('consultation_webrtc_offer')
def handle_consultation_webrtc_offer(data):
    """
    Relay a WebRTC offer to a specific peer within the consultation room.
    Data: { appointment_id, target_user_id, sdp }
    """
    if not current_user.is_authenticated:
        return
    try:
        target_user_id = int(data.get('target_user_id', 0))
        _emit_to_user(target_user_id, 'consultation_webrtc_offer', {
            'from_user_id': current_user.id,
            'sdp': data.get('sdp'),
            'appointment_id': data.get('appointment_id'),
        })
    except Exception as e:
        app.logger.error(f'consultation_webrtc_offer error: {e}')


@socketio.on('consultation_webrtc_answer')
def handle_consultation_webrtc_answer(data):
    """
    Relay a WebRTC answer back to the offer sender.
    Data: { appointment_id, target_user_id, sdp }
    """
    if not current_user.is_authenticated:
        return
    try:
        target_user_id = int(data.get('target_user_id', 0))
        _emit_to_user(target_user_id, 'consultation_webrtc_answer', {
            'from_user_id': current_user.id,
            'sdp': data.get('sdp'),
            'appointment_id': data.get('appointment_id'),
        })
    except Exception as e:
        app.logger.error(f'consultation_webrtc_answer error: {e}')


@socketio.on('consultation_webrtc_ice')
def handle_consultation_webrtc_ice(data):
    """
    Relay an ICE candidate to a specific peer.
    Data: { appointment_id, target_user_id, candidate }
    """
    if not current_user.is_authenticated:
        return
    try:
        target_user_id = int(data.get('target_user_id', 0))
        _emit_to_user(target_user_id, 'consultation_webrtc_ice', {
            'from_user_id': current_user.id,
            'candidate': data.get('candidate'),
            'appointment_id': data.get('appointment_id'),
        })
    except Exception as e:
        app.logger.error(f'consultation_webrtc_ice error: {e}')


@socketio.on('consultation_chat_message')
def handle_consultation_chat_message(data):
    """
    Broadcast a chat message to everyone in the consultation room.
    Data: { appointment_id, message, message_id }
    """
    if not current_user.is_authenticated:
        return
    try:
        appointment_id = int(data.get('appointment_id', 0))
        room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
        if not room:
            return

        room_socket_name = f'consultation:{room.room_token}'
        payload = {
            'from_user_id': current_user.id,
            'display_name': safe_display_name(current_user),
            'role': current_user.role,
            'profile_picture': get_user_profile_picture_url(current_user),
            'message': str(data.get('message', ''))[:2000],
            'message_id': data.get('message_id'),
            'appointment_id': appointment_id,
            'timestamp': now_eat().isoformat(),
        }
        emit('consultation_chat_message', payload, room=room_socket_name)
    except Exception as e:
        app.logger.error(f'consultation_chat_message error: {e}')


@socketio.on('consultation_whiteboard')
def handle_consultation_whiteboard(data):
    """
    Relay whiteboard canvas draw events to all room participants.
    Data: { appointment_id, action, x, y, color, size, ... }
    """
    if not current_user.is_authenticated:
        return
    try:
        appointment_id = int(data.get('appointment_id', 0))
        room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
        if not room:
            return
        room_socket_name = f'consultation:{room.room_token}'
        payload = dict(data)
        payload['from_user_id'] = current_user.id
        emit('consultation_whiteboard', payload, room=room_socket_name, include_self=False)
    except Exception as e:
        app.logger.error(f'consultation_whiteboard error: {e}')


@socketio.on('consultation_media_state')
def handle_consultation_media_state(data):
    """
    Broadcast mic/camera/screen-share toggle state to all room participants.
    Data: { appointment_id, audio_enabled, video_enabled, screen_sharing }
    """
    if not current_user.is_authenticated:
        return
    try:
        appointment_id = int(data.get('appointment_id', 0))
        room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
        if not room:
            return
        room_socket_name = f'consultation:{room.room_token}'
        emit('consultation_media_state', {
            'from_user_id': current_user.id,
            'audio_enabled': bool(data.get('audio_enabled', True)),
            'video_enabled': bool(data.get('video_enabled', True)),
            'screen_sharing': bool(data.get('screen_sharing', False)),
            'appointment_id': appointment_id,
        }, room=room_socket_name, include_self=False)
    except Exception as e:
        app.logger.error(f'consultation_media_state error: {e}')


@socketio.on('consultation_raise_hand')
def handle_consultation_raise_hand(data):
    """Patient raises hand to signal doctor. Data: { appointment_id, raised }"""
    if not current_user.is_authenticated:
        return
    try:
        appointment_id = int(data.get('appointment_id', 0))
        room = ConsultationRoom.query.filter_by(appointment_id=appointment_id).first()
        if not room:
            return
        room_socket_name = f'consultation:{room.room_token}'
        emit('consultation_raise_hand', {
            'from_user_id': current_user.id,
            'display_name': safe_display_name(current_user),
            'raised': bool(data.get('raised', True)),
            'appointment_id': appointment_id,
        }, room=room_socket_name)
    except Exception as e:
        app.logger.error(f'consultation_raise_hand error: {e}')


@socketio.on('send_notification')
def handle_send_notification(data):
    """Send a notification with optional sound"""
    if not current_user.is_authenticated:
        return
    
    try:
        recipient_id = data.get('recipient_id')
        notification_type = data.get('type')  # message, voice_call, video_call
        title = data.get('title')
        body = data.get('body')
        sound_enabled = data.get('sound_enabled', True)
        appointment_id = data.get('appointment_id')
        
        # Create notification in database
        notification = Notification(
            user_id=recipient_id,
            notification_type=notification_type,
            sender_id=current_user.id,
            title=title,
            body=body,
            sound_enabled=sound_enabled,
            appointment_id=appointment_id
        )
        db.session.add(notification)
        db.session.commit()
        
        # Send to recipient if online
        if _is_user_online(recipient_id):
            emit('notification_received', {
                'notification_id': notification.id,
                'type': notification_type,
                'title': title,
                'body': body,
                'sender_id': current_user.id,
                'sender_name': safe_display_name(current_user),
                'sound_enabled': sound_enabled,
                'appointment_id': appointment_id,
                'timestamp': notification.created_at.isoformat()
            }, room=f'user_{recipient_id}')
            
            return {'success': True, 'sent_immediately': True}
        else:
            return {'success': True, 'sent_immediately': False, 'queued': True}
    
    except Exception as e:
        print(f'Error sending notification: {str(e)}')
        emit('notification_error', {'error': str(e)})
        return {'success': False, 'error': str(e)}

@socketio.on('play_notification_sound')
def handle_play_notification_sound(data):
    """Trigger sound notification on client"""
    if not current_user.is_authenticated:
        return
    
    notification_type = data.get('type')  # message, voice_call, video_call
    
    # Broadcast sound event to the specific user
    recipient_id = data.get('recipient_id')
    if _is_user_online(recipient_id):
        emit('play_sound', {
            'type': notification_type,
            'timestamp': now_eat().isoformat()
        }, room=f'user_{recipient_id}')

@socketio.on('mark_notification_read')
def handle_mark_notification_read(data):
    """Mark notification as read"""
    if not current_user.is_authenticated:
        return
    
    try:
        notification_id = data.get('notification_id')
        notification = db.session.get(Notification, notification_id)
        
        if notification and notification.user_id == current_user.id:
            notification.is_read = True
            db.session.commit()
            return {'success': True}
    
    except Exception as e:
        print(f'Error marking notification as read: {str(e)}')
    
    return {'success': False}

@socketio.on('join_admin_chat')
def handle_join_admin_chat(data):
    """Join admin chat room"""
    if not current_user.is_authenticated:
        return {'error': 'Not authenticated'}
    if not _rate_limit(current_user.id, 'join_admin_chat', 10, 60):
        return {'error': 'rate_limited'}
    
    # Only allow patients and doctors to contact admins
    if current_user.role not in ['patient', 'doctor']:
        return {'error': 'Access denied'}
    
    admin_id = data.get('admin_id') if isinstance(data, dict) else None
    user_id = current_user.id
    user_role = current_user.role
    try:
        admin_id = int(admin_id)
    except Exception:
        return {'error': 'Invalid admin'}
    
    # Verify admin exists
    admin = db.session.get(User, admin_id)
    if not admin or admin.role != 'admin':
        return {'error': 'Invalid admin'}
    
    # Create room name for this conversation
    room_name = f'admin_chat_{min(user_id, admin_id)}_{max(user_id, admin_id)}'
    
    # Join the room
    join_room(room_name)
    
    # Notify admin that someone is chatting with them
    socketio.emit('admin_chat_started', {
        'user_id': user_id,
        'user_name': safe_display_name(current_user),
        'user_role': user_role,
        'timestamp': now_eat().isoformat()
    }, room=room_name)
    
    _log_event('join_admin_chat', user_id=user_id, admin_id=admin_id)
    return {'success': True, 'room': room_name}

@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    """Get user's notifications"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        include_read = request.args.get('include_read', 'false').lower() == 'true'
        # sanitize paging
        if per_page <= 0:
            per_page = 20
        if page <= 0:
            page = 1

        query = Notification.query.filter_by(user_id=current_user.id)
        if not include_read:
            query = query.filter_by(is_read=False)

        total = query.count()
        pages = max(1, math.ceil(total / per_page))
        notifications = query.order_by(Notification.created_at.desc()).offset((page-1)*per_page).limit(per_page).all()

        data = [{
            'id': n.id,
            'type': n.notification_type,
            'title': n.title,
            'body': n.body,
            'sender_id': n.sender_id,
            'sender_name': safe_display_name(n.sender) if n.sender else None,
            'appointment_id': n.appointment_id,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat()
        } for n in notifications]

        return jsonify({'success': True, 'notifications': data, 'total': total, 'page': page, 'pages': pages})
    
    except Exception as e:
        import traceback
        app.logger.error('Error in get_notifications: %s', e)
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a single notification as read"""
    try:
        notification = db.session.get(Notification, notification_id)
        
        if not notification or notification.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        notification.is_read = True
        db.session.commit()
        # emit updated unread count to user's room so other sessions update their badge
        try:
            unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
            socketio.emit('unread_count', {'unread_count': unread}, room=f'user_{current_user.id}')
        except Exception:
            pass
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        try:
            socketio.emit('unread_count', {'unread_count': 0}, room=f'user_{current_user.id}')
        except Exception:
            pass
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# PAYMENT MANAGEMENT API ROUTES
# ============================================

@app.route('/api/send-payment-reminder', methods=['POST'])
@login_required
@csrf.exempt
def send_payment_reminder_api():
    """Send payment reminder notification to patient"""
    try:
        data = request.get_json() or {}
        patient_id = data.get('patient_id')
        appointment_id = data.get('appointment_id')
        
        if not patient_id and not appointment_id:
            return jsonify({'success': False, 'error': 'Missing patient_id or appointment_id'}), 400
        
        # Get appointment
        if appointment_id:
            appointment = db.session.get(Appointment, appointment_id)
        else:
            # Find most recent unpaid appointment for patient
            appointment = db.session.query(Appointment).filter(
                Appointment.patient_id == patient_id,
                Appointment.payment_status == 'unpaid',
                Appointment.doctor_id == current_user.doctor.id
            ).order_by(Appointment.appointment_date.desc()).first()
        
        if not appointment:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
        # Verify doctor ownership
        if current_user.role == 'doctor' and appointment.doctor_id != current_user.doctor.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Send reminder
        success = send_payment_reminder_notification(appointment.id, appointment.doctor_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Payment reminder sent successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to send reminder'}), 500
    
    except Exception as e:
        db.session.rollback()
        print(f'Error sending payment reminder: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/mark-payment-complete', methods=['POST'])
@login_required
@csrf.exempt
def mark_payment_complete_api():
    """Mark consultation payment as complete"""
    try:
        data = request.get_json() or {}
        appointment_id = data.get('appointment_id')
        amount = data.get('amount')
        method = data.get('method', 'M-Pesa')
        
        if not appointment_id or not amount:
            return jsonify({'success': False, 'error': 'Missing appointment_id or amount'}), 400
        
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
        # Verify access - patient or admin
        if current_user.role == 'patient' and appointment.patient_id != current_user.patient.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if current_user.role not in ['patient', 'admin']:
            return jsonify({'success': False, 'error': 'Only patients and admin can mark payment'}), 403
        
        # Mark payment complete
        appointment.mark_payment_complete(amount, method)
        
        # Emit Socket.IO event
        try:
            socketio.emit('payment_completed', {
                'appointment_id': appointment_id,
                'amount': amount,
                'method': method
            }, broadcast=True)
        except Exception as e:
            print(f'Error emitting socket event: {e}')
        
        return jsonify({'success': True, 'message': 'Payment marked complete'})
    
    except Exception as e:
        db.session.rollback()
        print(f'Error marking payment: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/appointment-payment-status/<int:appointment_id>', methods=['GET'])
@login_required
def get_appointment_payment_api(appointment_id):
    """Get payment status for an appointment"""
    try:
        appointment = db.session.get(Appointment, appointment_id)
        if not appointment:
            return jsonify({'success': False, 'error': 'Appointment not found'}), 404
        
        # Check access
        if not (verify_appointment_access(appointment, current_user) or current_user.role == 'admin'):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        return jsonify({
            'success': True,
            'appointment_id': appointment_id,
            'payment_status': appointment.payment_status,
            'payment_amount': appointment.payment_amount,
            'payment_date': appointment.payment_date.isoformat() if appointment.payment_date else None,
            'payment_method': appointment.payment_method,
            'paid': appointment.payment_status == 'paid'
        })
    
    except Exception as e:
        print(f'Error getting payment status: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/unpaid-patients', methods=['GET'])
@login_required
def get_unpaid_patients_api():
    """Get list of unpaid patients for a doctor"""
    try:
        if current_user.role != 'doctor':
            return jsonify({'success': False, 'error': 'Only doctors can access this'}), 403
        
        unpaid = get_unpaid_patients_for_doctor(current_user.doctor.id)
        
        unpaid_data = []
        for appointment in unpaid:
            patient_user = appointment.patient.user
            unpaid_data.append({
                'id': appointment.id,
                'patient_id': appointment.patient_id,
                'patient_name': safe_display_name(patient_user),
                'appointment_date': appointment.appointment_date.isoformat(),
                'payment_amount': appointment.payment_amount or 0,
                'reminder_sent': appointment.reminder_sent_at is not None
            })
        
        return jsonify({'success': True, 'unpaid_patients': unpaid_data})
    
    except Exception as e:
        print(f'Error getting unpaid patients: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/notifications')
@login_required
def notifications_page():
    """Render a full notifications page. Page fetches data from /api/notifications."""
    try:
        return render_template('notifications.html')
    except Exception:
        return render_template('notifications.html')


# Duplicate testimonial route removed — canonical handler is submit_testimonial_for_appointment above


# --------------------
# User call permissions API
# --------------------
@app.route('/api/user/permissions', methods=['GET'])
@login_required
def get_user_permissions():
    try:
        user = db.session.get(User, current_user.id)
        if not user:
            return jsonify({'error': 'user_not_found'}), 404

        return jsonify({
            'call_permissions_granted': bool(getattr(user, 'call_permissions_granted', False)),
            'call_permissions_granted_at': user.call_permissions_granted_at.isoformat() if getattr(user, 'call_permissions_granted_at', None) else None,
            'last_known_lat': getattr(user, 'last_known_lat', None),
            'last_known_lng': getattr(user, 'last_known_lng', None),
            'last_known_timezone': getattr(user, 'last_known_timezone', None)
        })
    except Exception as e:
        app.logger.exception('Failed to get user permissions')
        return jsonify({'error': 'server_error', 'message': str(e)}), 500


@app.route('/api/user/permissions', methods=['POST'])
@login_required
def update_user_permissions():
    try:
        data = request.get_json() or {}
        user = db.session.get(User, current_user.id)
        if not user:
            return jsonify({'error': 'user_not_found'}), 404

        granted = bool(data.get('call_permissions_granted', False))
        user.call_permissions_granted = granted
        if granted:
            user.call_permissions_granted_at = now_eat()

        lat = data.get('last_known_lat')
        lng = data.get('last_known_lng')
        tz = data.get('last_known_timezone')
        if lat is not None:
            try:
                user.last_known_lat = float(lat)
            except Exception:
                pass
        if lng is not None:
            try:
                user.last_known_lng = float(lng)
            except Exception:
                pass
        if tz:
            user.last_known_timezone = str(tz)

        db.session.add(user)
        db.session.commit()

        try:
            socketio.emit('user_permissions_updated', {'user_id': user.id, 'call_permissions_granted': user.call_permissions_granted}, room=f'user_{user.id}')
        except Exception:
            pass

        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to update user permissions')
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== HEALTH TIPS ENDPOINTS ====================

@app.route('/api/health-tips/patient/<int:patient_id>', methods=['GET'])
@login_required
def get_patient_health_tips(patient_id):
    """Get all health tips for a patient (accessible by doctor and patient)"""
    try:
        patient = db.session.get(Patient, patient_id)
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Check authorization: patient can view own tips, doctor can view tips for their patients
        if current_user.id != patient.user_id and current_user.role == 'patient':
            return jsonify({'error': 'Access denied'}), 403
        
        if current_user.role == 'doctor':
            doctor = Doctor.query.filter_by(user_id=current_user.id).first()
            if not doctor:
                return jsonify({'error': 'Doctor profile not found'}), 403
        
        # Get all health tips for this patient
        health_tips = HealthTip.query.filter_by(patient_id=patient_id).order_by(
            HealthTip.created_at.desc()
        ).all()
        
        tips_data = []
        for tip in health_tips:
            tips_data.append({
                'id': tip.id,
                'title': tip.title,
                'description': tip.description,
                'doctor_id': tip.doctor_id,
                'doctor_name': tip.doctor.user.first_name + ' ' + tip.doctor.user.last_name,
                'appointment_id': tip.appointment_id,
                'created_at': tip.created_at.isoformat(),
                'updated_at': tip.updated_at.isoformat()
            })
        
        return jsonify({'health_tips': tips_data, 'total': len(tips_data)})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    # NOTE: duplicate appointment-specific testimonial route removed (kept canonical /api/appointments/<id>/testimonial earlier)


@app.route('/api/health-tips', methods=['POST'])
@login_required
def create_health_tip():
    """Create a new health tip (doctor only)"""
    try:
        if current_user.role != 'doctor':
            return jsonify({'error': 'Only doctors can create health tips'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required_fields = ['patient_id', 'title', 'description']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if not doctor:
            return jsonify({'error': 'Doctor profile not found'}), 404
        
        patient = db.session.get(Patient, data['patient_id'])
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Create new health tip
        health_tip = HealthTip(
            doctor_id=doctor.id,
            patient_id=patient.id,
            appointment_id=data.get('appointment_id'),
            title=data['title'],
            description=data['description']
        )
        
        db.session.add(health_tip)
        db.session.commit()
        
        # Emit real-time notification to patient (emit to personal room)
        patient_user = db.session.get(User, patient.user_id)
        if patient_user:
            # Use the Socket.IO server instance to emit from a Flask route (request context has no namespace)
            socketio.emit('new_health_tip', {
                'tip_id': health_tip.id,
                'title': health_tip.title,
                'doctor_name': current_user.first_name + ' ' + current_user.last_name
            }, room=f'user_{patient_user.id}')
        
        return jsonify({
            'success': True,
            'health_tip_id': health_tip.id,
            'message': 'Health tip created successfully'
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/health-tips/<int:tip_id>', methods=['PUT'])
@login_required
def update_health_tip(tip_id):
    """Update a health tip (doctor only)"""
    try:
        if current_user.role != 'doctor':
            return jsonify({'error': 'Only doctors can update health tips'}), 403
        
        health_tip = db.session.get(HealthTip, tip_id)
        if not health_tip:
            return jsonify({'error': 'Health tip not found'}), 404
        
        # Check authorization: only creator doctor can update
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if health_tip.doctor_id != doctor.id:
            return jsonify({'error': 'You can only edit your own health tips'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields
        if 'title' in data:
            health_tip.title = data['title']
        if 'description' in data:
            health_tip.description = data['description']
        
        health_tip.updated_at = now_eat()
        db.session.commit()
        
        # Emit real-time notification to patient
        patient = db.session.get(Patient, health_tip.patient_id)
        patient_user = db.session.get(User, patient.user_id)
        if patient_user:
            # Emit from Flask route using socketio server instance
            socketio.emit('health_tip_updated', {
                'tip_id': health_tip.id,
                'title': health_tip.title,
                'doctor_name': current_user.first_name + ' ' + current_user.last_name
            }, room=f'user_{patient_user.id}')
        
        return jsonify({'success': True, 'message': 'Health tip updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/health-tips/<int:tip_id>', methods=['DELETE'])
@login_required
def delete_health_tip(tip_id):
    """Delete a health tip (doctor only)"""
    try:
        if current_user.role != 'doctor':
            return jsonify({'error': 'Only doctors can delete health tips'}), 403
        
        health_tip = db.session.get(HealthTip, tip_id)
        if not health_tip:
            return jsonify({'error': 'Health tip not found'}), 404
        
        # Check authorization: only creator doctor can delete
        doctor = Doctor.query.filter_by(user_id=current_user.id).first()
        if health_tip.doctor_id != doctor.id:
            return jsonify({'error': 'You can only delete your own health tips'}), 403
        
        patient_id = health_tip.patient_id
        db.session.delete(health_tip)
        db.session.commit()
        
        # Emit real-time notification to patient
        patient = db.session.get(Patient, patient_id)
        patient_user = db.session.get(User, patient.user_id)
        if patient_user:
            # Emit from Flask route using socketio server instance
            socketio.emit('health_tip_deleted', {
                'tip_id': tip_id,
                'doctor_name': current_user.first_name + ' ' + current_user.last_name
            }, room=f'user_{patient_user.id}')
        
        return jsonify({'success': True, 'message': 'Health tip deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@socketio.on('health_tip_viewed')
def handle_health_tip_viewed(data):
    """Handle when patient views a health tip"""
    try:
        tip_id = data.get('tip_id')
        health_tip = db.session.get(HealthTip, tip_id)
        
        if health_tip:
            patient = db.session.get(Patient, health_tip.patient_id)
            if patient.user_id == current_user.id:
                # Emit to doctor that patient viewed the tip
                doctor_user = db.session.get(User, health_tip.doctor.user_id)
                if doctor_user:
                    emit('patient_viewed_health_tip', {
                        'tip_id': tip_id,
                        'patient_name': current_user.first_name + ' ' + current_user.last_name
                    }, room=f'user_{doctor_user.id}')
    except Exception as e:
        print(f"Error handling health tip viewed: {e}")


@app.cli.command('dispatch-day-reminders')
@click.option('--date', 'date_text', default=None, help='Target date in YYYY-MM-DD format (defaults to today in EAT).')
@click.option('--dry-run', is_flag=True, default=False, help='Preview eligible reminders without sending emails.')
def dispatch_day_reminders_command(date_text, dry_run):
    """Manually trigger appointment day-reminder dispatch for operational checks."""
    try:
        if date_text:
            try:
                target_date = date.fromisoformat(str(date_text).strip())
            except Exception:
                raise click.ClickException('Invalid --date. Use YYYY-MM-DD.')
        else:
            target_date = now_eat().date()

        stats = dispatch_day_of_appointment_reminders(target_date=target_date, dry_run=dry_run)
        click.echo(_json.dumps({'success': True, 'stats': stats}, indent=2))
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))


# ============================================
# SUPPORT CALL SIGNALING (customer care WebRTC)
# ============================================

@socketio.on('join_support_call')
def handle_join_support_call(data):
    """User or agent joins a support call room."""
    if not current_user.is_authenticated:
        return
    room = (data or {}).get('room', '')
    if not room or not room.startswith('support_call_'):
        emit('error', {'message': 'Invalid room'})
        return
    try:
        conv_id = int(room.split('_')[-1])
    except (ValueError, IndexError):
        emit('error', {'message': 'Invalid room'})
        return
    conv = db.session.get(SupportConversation, conv_id)
    if not conv:
        emit('error', {'message': 'Not found'})
        return
    if current_user.id != conv.user_id and current_user.role not in ('customer_care', 'admin'):
        emit('error', {'message': 'Access denied'})
        return
    join_room(room)
    # Count peers in the room
    try:
        room_clients = socketio.server.manager.get_participants('/', room)
        peer_count = len(list(room_clients))
    except Exception:
        peer_count = 1
    emit('support_call_joined', {'peer_count': peer_count}, room=request.sid)
    if peer_count > 1:
        emit('support_call_peer_joined', {'user_id': current_user.id}, room=room, skip_sid=request.sid)


@socketio.on('support_offer')
def handle_support_offer(data):
    if not current_user.is_authenticated:
        return
    room = (data or {}).get('room', '')
    if room.startswith('support_call_'):
        emit('support_offer', {'offer': data.get('offer')}, room=room, skip_sid=request.sid)


@socketio.on('support_answer')
def handle_support_answer(data):
    if not current_user.is_authenticated:
        return
    room = (data or {}).get('room', '')
    if room.startswith('support_call_'):
        emit('support_answer', {'answer': data.get('answer')}, room=room, skip_sid=request.sid)


@socketio.on('support_ice')
def handle_support_ice(data):
    if not current_user.is_authenticated:
        return
    room = (data or {}).get('room', '')
    if room.startswith('support_call_'):
        emit('support_ice', {'candidate': data.get('candidate')}, room=room, skip_sid=request.sid)


@socketio.on('support_call_end')
def handle_support_call_end(data):
    if not current_user.is_authenticated:
        return
    room = (data or {}).get('room', '')
    if room.startswith('support_call_'):
        emit('support_call_ended', {}, room=room)
        leave_room(room)


if __name__ == '__main__':
    cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
    cleanup_thread.start()
    
    port = int(os.environ.get('PORT', 5000))
    
    # Use the detected async backend name in the startup message
    async_backend = getattr(socketio.server, 'async_mode', None) or 'async'
    print(f"🚀 Starting application on port {port} with async backend={async_backend}")

    try:
        use_reloader = False
        if SOCKETIO_AVAILABLE:
            socketio.run(
                app,
                host='0.0.0.0',
                port=port,
                debug=debug_mode,
                log_output=debug_mode,
                allow_unsafe_werkzeug=debug_mode,
                use_reloader=use_reloader
            )
        else:
            from gevent.pywsgi import WSGIServer
            http_server = WSGIServer(('0.0.0.0', port), app)
            print(f"Server starting on port {port}")
            http_server.serve_forever()
    except TypeError:
        if SOCKETIO_AVAILABLE:
            socketio.run(
                app,
                host='0.0.0.0',
                port=port,
                debug=debug_mode,
                log_output=debug_mode,
                allow_unsafe_werkzeug=debug_mode
            )
        else:
            from gevent.pywsgi import WSGIServer
            http_server = WSGIServer(('0.0.0.0', port), app)
            print(f"Server starting on port {port}")
            http_server.serve_forever()
