"""
Call Logs & Quality Metrics API
Unified endpoints for call history, statistics, and quality metrics.
Used by doctors, patients, and admin dashboards.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timezone, timedelta
from models import (
    db, User, CallHistory, CallQualityMetrics, Doctor, Patient, Appointment
)
from sqlalchemy import and_, or_, desc, func

communication_bp = Blueprint('communication', __name__, url_prefix='/api')


# ──────────────────────────────────────────────────────────
# CALL LOGS  (unified endpoint for all roles)
# ──────────────────────────────────────────────────────────

@communication_bp.route('/call-logs', methods=['GET'])
@login_required
def get_call_logs():
    """Return call logs with comprehensive filtering.

    Query params:
        filter   – all | incoming | outgoing | missed | declined  (default: all)
        call_type – voice | video
        status   – completed | missed | declined | failed | ringing | connected | ended
        start_date / end_date – YYYY-MM-DD inclusive range
        doctor_id / patient_id – admin-only appointment-level filter
        page     – pagination page (default 1)
        per_page – items per page (default 25, max 100)
    """
    try:
        page = min(max(request.args.get('page', 1, type=int), 1), 10000)
        per_page = min(max(request.args.get('per_page', 25, type=int), 1), 100)
        filter_by = (request.args.get('filter') or 'all').strip().lower()
        call_type = (request.args.get('call_type') or '').strip().lower()
        status_filter = (request.args.get('status') or '').strip().lower()
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        doctor_id = request.args.get('doctor_id', type=int)
        patient_id = request.args.get('patient_id', type=int)

        q = CallHistory.query

        # Non-admins see only their own calls
        if current_user.role != 'admin':
            q = q.filter(or_(
                CallHistory.caller_id == current_user.id,
                CallHistory.callee_id == current_user.id
            ))

        # Direction / disposition filter
        if filter_by == 'incoming':
            q = q.filter(CallHistory.callee_id == current_user.id)
        elif filter_by == 'outgoing':
            q = q.filter(CallHistory.caller_id == current_user.id)
        elif filter_by == 'missed':
            q = q.filter(CallHistory.end_reason.in_(
                ['missed', 'unanswered', 'timeout']
            ))
        elif filter_by == 'declined':
            q = q.filter(CallHistory.end_reason.in_(
                ['callee_declined', 'declined', 'rejected']
            ))

        # Call type
        if call_type in ('voice', 'video'):
            q = q.filter(CallHistory.call_type == call_type)

        # Date range
        if start_date:
            try:
                q = q.filter(CallHistory.initiated_at >= datetime.fromisoformat(start_date))
            except (ValueError, TypeError):
                pass
        if end_date:
            try:
                q = q.filter(CallHistory.initiated_at < datetime.fromisoformat(end_date) + timedelta(days=1))
            except (ValueError, TypeError):
                pass

        # Admin appointment-level filters
        if current_user.role == 'admin':
            joined = False
            if doctor_id is not None:
                q = q.join(Appointment, Appointment.id == CallHistory.appointment_id)
                joined = True
                q = q.filter(Appointment.doctor_id == doctor_id)
            if patient_id is not None:
                if not joined:
                    q = q.join(Appointment, Appointment.id == CallHistory.appointment_id)
                q = q.filter(Appointment.patient_id == patient_id)

        # Status filter
        _status_map = {
            'completed': lambda q: q.filter(or_(CallHistory.end_reason == 'user_hangup', CallHistory.status == 'ended', CallHistory.end_reason == 'completed')),
            'missed':    lambda q: q.filter(CallHistory.end_reason.in_(['missed', 'unanswered', 'timeout'])),
            'declined':  lambda q: q.filter(CallHistory.end_reason.in_(['rejected', 'declined', 'callee_declined', 'user_declined'])),
            'failed':    lambda q: q.filter(CallHistory.end_reason.in_(['connection_failed', 'failed_network', 'network_error'])),
            'busy':      lambda q: q.filter(CallHistory.end_reason == 'busy'),
        }
        if status_filter in _status_map:
            q = _status_map[status_filter](q)
        elif status_filter in ('ringing', 'accepted', 'connected', 'ended', 'initiated'):
            q = q.filter(CallHistory.status == status_filter)

        total = q.count()
        items = q.order_by(desc(CallHistory.initiated_at)).offset(
            (page - 1) * per_page
        ).limit(per_page).all()

        calls = []
        for c in items:
            d = c.to_dict()
            # Ensure caller/callee names are always present for admin view
            if current_user.role == 'admin':
                caller = db.session.get(User, c.caller_id)
                callee = db.session.get(User, c.callee_id)
                d['caller_name'] = caller.get_display_name() if caller else 'Unknown'
                d['callee_name'] = callee.get_display_name() if callee else 'Unknown'
                d['remote_user_id'] = c.callee_id if c.caller_id == current_user.id else c.caller_id
            calls.append(d)

        return jsonify({
            'success': True,
            'call_logs': calls,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@communication_bp.route('/call-logs/<int:call_id>', methods=['GET'])
@login_required
def get_call_detail(call_id):
    """Get full detail for a single call including quality metrics."""
    try:
        call = db.session.get(CallHistory, call_id)
        if not call:
            return jsonify({'success': False, 'error': 'Call not found'}), 404

        if (current_user.id != call.caller_id and
                current_user.id != call.callee_id and
                current_user.role != 'admin'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        data = call.to_dict()

        # Add both user names for detailed view
        caller = db.session.get(User, call.caller_id)
        callee = db.session.get(User, call.callee_id)
        data['caller_name'] = caller.get_display_name() if caller else 'Unknown'
        data['callee_name'] = callee.get_display_name() if callee else 'Unknown'

        # Quality metrics for this call
        metrics = CallQualityMetrics.query.filter_by(call_id=call.call_id).all()
        data['quality_metrics_detailed'] = [m.to_dict() for m in metrics]

        return jsonify({'success': True, 'call': data})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


# ──────────────────────────────────────────────────────────
# STATISTICS
# ──────────────────────────────────────────────────────────

@communication_bp.route('/call-statistics', methods=['GET'])
@login_required
def get_call_statistics():
    """Aggregated call stats for the current user (or all calls for admin).

    Query params:
        period – 7d | 30d | 90d | all  (default 30d)
    """
    try:
        period = (request.args.get('period') or '30d').strip().lower()
        period_map = {'7d': 7, '30d': 30, '90d': 90}
        since = None
        if period in period_map:
            since = datetime.now(timezone.utc) - timedelta(days=period_map[period])

        base = CallHistory.query
        if current_user.role != 'admin':
            base = base.filter(or_(
                CallHistory.caller_id == current_user.id,
                CallHistory.callee_id == current_user.id
            ))
        if since:
            base = base.filter(CallHistory.initiated_at >= since)

        total = base.count()
        completed = base.filter(or_(
            CallHistory.status == 'ended',
            CallHistory.end_reason == 'user_hangup'
        )).count()
        missed = base.filter(CallHistory.end_reason.in_(['missed', 'timeout', 'unanswered'])).count()
        declined = base.filter(CallHistory.end_reason.in_(['callee_declined', 'declined', 'rejected'])).count()
        video = base.filter(CallHistory.call_type == 'video').count()
        voice = base.filter(CallHistory.call_type == 'voice').count()

        avg_dur = base.filter(CallHistory.duration.isnot(None)).with_entities(
            func.avg(CallHistory.duration)
        ).scalar()

        # Longest call
        longest = base.filter(CallHistory.duration.isnot(None)).with_entities(
            func.max(CallHistory.duration)
        ).scalar()

        # Total talk time
        total_talk = base.filter(CallHistory.duration.isnot(None)).with_entities(
            func.sum(CallHistory.duration)
        ).scalar()

        return jsonify({
            'success': True,
            'statistics': {
                'period': period,
                'total_calls': total,
                'completed_calls': completed,
                'missed_calls': missed,
                'declined_calls': declined,
                'video_calls': video,
                'voice_calls': voice,
                'average_duration': int(avg_dur) if avg_dur else 0,
                'longest_call': int(longest) if longest else 0,
                'total_talk_time': int(total_talk) if total_talk else 0
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


# ──────────────────────────────────────────────────────────
# QUALITY METRICS
# ──────────────────────────────────────────────────────────

@communication_bp.route('/calls/<call_id>/quality-metrics', methods=['POST'])
@login_required
def submit_quality_metrics(call_id):
    """Submit quality metrics for a call (client-side WebRTC stats)."""
    try:
        call = CallHistory.query.filter_by(call_id=call_id).first()
        if not call:
            return jsonify({'success': False, 'error': 'Call not found'}), 404

        if current_user.id not in (call.caller_id, call.callee_id):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        data = request.get_json() or {}

        metrics = CallQualityMetrics(
            call_id=call_id,
            user_id=current_user.id,
            rtt=data.get('rtt'),
            packet_loss=data.get('packet_loss'),
            jitter=data.get('jitter'),
            available_bandwidth=data.get('available_bandwidth'),
            audio_bitrate=data.get('audio_bitrate'),
            video_bitrate=data.get('video_bitrate'),
            video_resolution=data.get('video_resolution'),
            video_framerate=data.get('video_framerate'),
            cpu_usage=data.get('cpu_usage'),
            memory_usage=data.get('memory_usage'),
            audio_quality=data.get('audio_quality'),
            video_quality=data.get('video_quality'),
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(metrics)

        # Update JSON summary on CallHistory
        if not call.quality_metrics:
            call.quality_metrics = {}
        call.quality_metrics[str(current_user.id)] = {
            'rtt': metrics.rtt,
            'packet_loss': metrics.packet_loss,
            'audio_quality': metrics.audio_quality,
            'video_quality': metrics.video_quality
        }

        db.session.commit()
        return jsonify({'success': True, 'metrics': metrics.to_dict()})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400


@communication_bp.route('/calls/<call_id>/quality-metrics', methods=['GET'])
@login_required
def get_quality_metrics(call_id):
    """Retrieve quality metrics for a specific call."""
    try:
        call = CallHistory.query.filter_by(call_id=call_id).first()
        if not call:
            return jsonify({'success': False, 'error': 'Call not found'}), 404

        if (current_user.id not in (call.caller_id, call.callee_id) and
                current_user.role != 'admin'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        metrics = CallQualityMetrics.query.filter_by(call_id=call_id).all()
        return jsonify({'success': True, 'metrics': [m.to_dict() for m in metrics]})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


# ──────────────────────────────────────────────────────────
# MISSED-CALL NOTIFICATIONS  (polled by browser)
# ──────────────────────────────────────────────────────────

@communication_bp.route('/missed-calls', methods=['GET'])
@login_required
def get_missed_calls():
    """Return recent missed calls for browser notification polling.

    Query params:
        since – ISO datetime; only return calls after this time (default: last 5 min)
    """
    try:
        since_str = request.args.get('since')
        if since_str:
            try:
                since = datetime.fromisoformat(since_str)
            except (ValueError, TypeError):
                since = datetime.now(timezone.utc) - timedelta(minutes=5)
        else:
            since = datetime.now(timezone.utc) - timedelta(minutes=5)

        calls = CallHistory.query.filter(
            CallHistory.callee_id == current_user.id,
            CallHistory.end_reason.in_(['missed', 'timeout', 'unanswered']),
            CallHistory.initiated_at >= since
        ).order_by(desc(CallHistory.initiated_at)).limit(20).all()

        return jsonify({
            'success': True,
            'missed_calls': [c.to_dict() for c in calls]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400
