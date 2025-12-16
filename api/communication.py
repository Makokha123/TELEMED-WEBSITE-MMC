"""
Real-Time Communication API Endpoints
Handles call signaling, messaging, presence, and call history
"""

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timezone, timedelta
from models import (
    db, User, Appointment, CallHistory, Message, Conversation, 
    Attachment, CallQualityMetrics, UserPresence, Doctor, Patient
)
from sqlalchemy import and_, or_, desc, func
import os
import uuid
from werkzeug.utils import secure_filename

# Create Blueprint
communication_bp = Blueprint('communication', __name__, url_prefix='/api')

# ============================================
# CALL HISTORY API
# ============================================

@communication_bp.route('/call-history', methods=['GET'])
@login_required
def get_call_history():
    """Get call history for current user with filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        call_type = request.args.get('call_type', None)  # 'video' or 'voice'
        status = request.args.get('status', None)
        date_from = request.args.get('date_from', None)
        date_to = request.args.get('date_to', None)

        query = CallHistory.query.filter(
            or_(
                CallHistory.caller_id == current_user.id,
                CallHistory.callee_id == current_user.id
            )
        )

        # Apply filters
        if call_type:
            query = query.filter_by(call_type=call_type)
        if status:
            query = query.filter_by(status=status)
        if date_from:
            date_from_obj = datetime.fromisoformat(date_from)
            query = query.filter(CallHistory.initiated_at >= date_from_obj)
        if date_to:
            date_to_obj = datetime.fromisoformat(date_to)
            query = query.filter(CallHistory.initiated_at <= date_to_obj)

        # Sort by most recent first
        query = query.order_by(desc(CallHistory.initiated_at))

        # Paginate
        pagination = query.paginate(page=page, per_page=per_page)

        calls = [call.to_dict() for call in pagination.items]

        return jsonify({
            'success': True,
            'calls': calls,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@communication_bp.route('/call-history/<int:call_id>', methods=['GET'])
@login_required
def get_call_detail(call_id):
    """Get detailed information about a specific call"""
    try:
        call = CallHistory.query.get(call_id)
        if not call:
            return jsonify({'success': False, 'error': 'Call not found'}), 404

        # Check access (only participants and admins can view)
        if (current_user.id != call.caller_id and 
            current_user.id != call.callee_id and 
            current_user.role != 'admin'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        call_data = call.to_dict()
        
        # Include quality metrics
        quality_metrics = CallQualityMetrics.query.filter_by(
            call_id=call.call_id
        ).all()
        call_data['quality_metrics'] = [m.to_dict() for m in quality_metrics]

        return jsonify({
            'success': True,
            'call': call_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@communication_bp.route('/call-statistics', methods=['GET'])
@login_required
def get_call_statistics():
    """Get call statistics for current user"""
    try:
        # Time filters
        period = request.args.get('period', '30d')  # 7d, 30d, 90d, all
        
        if period == '7d':
            since = datetime.now(timezone.utc) - timedelta(days=7)
        elif period == '30d':
            since = datetime.now(timezone.utc) - timedelta(days=30)
        elif period == '90d':
            since = datetime.now(timezone.utc) - timedelta(days=90)
        else:
            since = None

        query = CallHistory.query.filter(
            or_(
                CallHistory.caller_id == current_user.id,
                CallHistory.callee_id == current_user.id
            )
        )

        if since:
            query = query.filter(CallHistory.initiated_at >= since)

        # Statistics
        total_calls = query.count()
        completed_calls = query.filter_by(status='ended').count()
        missed_calls = query.filter_by(end_reason='missed').count()
        declined_calls = query.filter_by(end_reason='callee_declined').count()
        
        video_calls = query.filter_by(call_type='video').count()
        voice_calls = query.filter_by(call_type='voice').count()

        # Average duration
        avg_duration_result = db.session.query(
            func.avg(CallHistory.duration)
        ).filter(
            and_(
                or_(
                    CallHistory.caller_id == current_user.id,
                    CallHistory.callee_id == current_user.id
                ),
                CallHistory.duration.isnot(None)
            )
        ).scalar() if since is None else query.filter(
            CallHistory.duration.isnot(None)
        ).with_entities(func.avg(CallHistory.duration)).scalar()

        avg_duration = int(avg_duration_result) if avg_duration_result else 0

        return jsonify({
            'success': True,
            'statistics': {
                'period': period,
                'total_calls': total_calls,
                'completed_calls': completed_calls,
                'missed_calls': missed_calls,
                'declined_calls': declined_calls,
                'video_calls': video_calls,
                'voice_calls': voice_calls,
                'average_duration': avg_duration
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


# ============================================
# MESSAGING API
# ============================================

@communication_bp.route('/conversations', methods=['GET'])
@login_required
def get_conversations():
    """Get all conversations for current user"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Query conversations where user is a participant
        query = Conversation.query.filter(
            Conversation.participant_ids.contains(str(current_user.id))
        ).order_by(desc(Conversation.last_message_at))

        pagination = query.paginate(page=page, per_page=per_page)

        conversations = [conv.to_dict() for conv in pagination.items]

        return jsonify({
            'success': True,
            'conversations': conversations,
            'total': pagination.total,
            'pages': pagination.pages
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@communication_bp.route('/conversations/<int:conversation_id>/messages', methods=['GET'])
@login_required
def get_conversation_messages(conversation_id):
    """Get messages in a conversation"""
    try:
        conversation = Conversation.query.get(conversation_id)
        if not conversation:
            return jsonify({'success': False, 'error': 'Conversation not found'}), 404

        # Check access
        if current_user.id not in conversation.participant_ids:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)

        messages = Message.query.filter_by(
            conversation_id=conversation_id
        ).order_by(Message.created_at).paginate(
            page=page, per_page=per_page
        )

        message_data = [msg.to_dict() for msg in messages.items]

        return jsonify({
            'success': True,
            'messages': message_data,
            'total': messages.total,
            'pages': messages.pages
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@communication_bp.route('/conversations/<int:conversation_id>/send-message', methods=['POST'])
@login_required
def send_message(conversation_id):
    """Send a message in a conversation"""
    try:
        conversation = Conversation.query.get(conversation_id)
        if not conversation:
            return jsonify({'success': False, 'error': 'Conversation not found'}), 404

        # Check access
        if current_user.id not in conversation.participant_ids:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        data = request.get_json()
        body = data.get('body', '').strip()
        message_type = data.get('message_type', 'text')
        call_id = data.get('call_id')

        if not body and message_type == 'text':
            return jsonify({'success': False, 'error': 'Message body required'}), 400

        # Create message
        message = Message(
            message_id=str(uuid.uuid4()),
            conversation_id=conversation_id,
            sender_id=current_user.id,
            body=body if message_type == 'text' else None,
            message_type=message_type,
            in_call=(call_id is not None),
            call_id=call_id,
            status='sent'
        )

        db.session.add(message)

        # Update conversation last_message_at
        conversation.last_message_at = datetime.now(timezone.utc)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': message.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@communication_bp.route('/messages/<int:message_id>/mark-read', methods=['POST'])
@login_required
def mark_message_read(message_id):
    """Mark a message as read"""
    try:
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'success': False, 'error': 'Message not found'}), 404

        # Check access
        if message.conversation.participant_ids and current_user.id not in message.conversation.participant_ids:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        message.status = 'read'
        message.read_at = datetime.now(timezone.utc)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': message.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


# ============================================
# PRESENCE API
# ============================================

@communication_bp.route('/presence/update', methods=['POST'])
@login_required
def update_presence():
    """Update user presence status"""
    try:
        data = request.get_json()
        status = data.get('status', 'online')  # online, away, idle, busy, offline, do_not_disturb
        current_call_id = data.get('current_call_id')
        current_appointment_id = data.get('current_appointment_id')

        # Get or create presence record
        presence = UserPresence.query.filter_by(user_id=current_user.id).first()
        if not presence:
            presence = UserPresence(user_id=current_user.id)
            db.session.add(presence)

        presence.status = status
        presence.current_call_id = current_call_id
        presence.current_appointment_id = current_appointment_id
        presence.last_heartbeat = datetime.now(timezone.utc)
        presence.last_seen = datetime.now(timezone.utc)

        db.session.commit()

        return jsonify({
            'success': True,
            'presence': presence.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@communication_bp.route('/presence/<int:user_id>', methods=['GET'])
@login_required
def get_presence(user_id):
    """Get presence status of a user"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        presence = UserPresence.query.filter_by(user_id=user_id).first()
        if not presence:
            # Return default offline status
            return jsonify({
                'success': True,
                'presence': {
                    'user_id': user_id,
                    'status': 'offline',
                    'last_seen': user.created_at.isoformat() if user.created_at else None
                }
            })

        return jsonify({
            'success': True,
            'presence': presence.to_dict()
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


# ============================================
# ATTACHMENT API
# ============================================

@communication_bp.route('/attachments/upload', methods=['POST'])
@login_required
def upload_attachment():
    """Upload a file attachment"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400

        file = request.files['file']
        call_id = request.form.get('call_id')
        message_id = request.form.get('message_id')
        access_control = request.form.get('access_control', 'private')

        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400

        # Validate file size (max 50MB)
        MAX_FILE_SIZE = 50 * 1024 * 1024
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning

        if file_size > MAX_FILE_SIZE:
            return jsonify({'success': False, 'error': 'File too large'}), 400

        # Allowed extensions
        ALLOWED_EXTENSIONS = {
            'pdf', 'doc', 'docx', 'txt', 'xlsx', 'xls',
            'jpg', 'jpeg', 'png', 'gif', 'webp',
            'mp3', 'wav', 'm4a',
            'mp4', 'mov', 'webm'
        }

        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

        if file_ext not in ALLOWED_EXTENSIONS:
            return jsonify({'success': False, 'error': 'File type not allowed'}), 400

        # Generate S3 key
        attachment_id = str(uuid.uuid4())
        s3_key = f"attachments/{current_user.id}/{attachment_id}/{filename}"

        # For now, save locally (integrate S3 in production)
        upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'attachments')
        os.makedirs(upload_folder, exist_ok=True)

        file_path = os.path.join(upload_folder, attachment_id, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        file.save(file_path)

        # Create attachment record
        attachment = Attachment(
            attachment_id=attachment_id,
            owner_id=current_user.id,
            file_name=filename,
            file_type=file.content_type or 'application/octet-stream',
            file_size=file_size,
            s3_key=s3_key,
            s3_bucket='local',
            file_url=f'/uploads/attachments/{attachment_id}/{filename}',
            shared_in_call_id=call_id,
            shared_in_message_id=message_id if message_id else None,
            access_control=access_control,
            is_encrypted=True
        )

        db.session.add(attachment)
        db.session.commit()

        return jsonify({
            'success': True,
            'attachment': attachment.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@communication_bp.route('/attachments/<attachment_id>', methods=['GET'])
@login_required
def get_attachment(attachment_id):
    """Get attachment details"""
    try:
        attachment = Attachment.query.filter_by(
            attachment_id=attachment_id
        ).first()

        if not attachment:
            return jsonify({'success': False, 'error': 'Attachment not found'}), 404

        # Check access based on access_control
        if attachment.access_control == 'private' and attachment.owner_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        return jsonify({
            'success': True,
            'attachment': attachment.to_dict()
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


# ============================================
# QUALITY METRICS API
# ============================================

@communication_bp.route('/calls/<call_id>/quality-metrics', methods=['POST'])
@login_required
def submit_quality_metrics(call_id):
    """Submit quality metrics for a call"""
    try:
        call = CallHistory.query.filter_by(call_id=call_id).first()
        if not call:
            return jsonify({'success': False, 'error': 'Call not found'}), 404

        # Check access
        if (current_user.id != call.caller_id and 
            current_user.id != call.callee_id):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        data = request.get_json()

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

        # Update call's overall quality metrics in JSON
        if not call.quality_metrics:
            call.quality_metrics = {}

        call.quality_metrics[str(current_user.id)] = {
            'rtt': metrics.rtt,
            'packet_loss': metrics.packet_loss,
            'audio_quality': metrics.audio_quality,
            'video_quality': metrics.video_quality
        }

        db.session.commit()

        return jsonify({
            'success': True,
            'metrics': metrics.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@communication_bp.route('/calls/<call_id>/quality-metrics', methods=['GET'])
@login_required
def get_quality_metrics(call_id):
    """Get quality metrics for a call"""
    try:
        call = CallHistory.query.filter_by(call_id=call_id).first()
        if not call:
            return jsonify({'success': False, 'error': 'Call not found'}), 404

        # Check access
        if (current_user.id != call.caller_id and 
            current_user.id != call.callee_id and
            current_user.role != 'admin'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        metrics = CallQualityMetrics.query.filter_by(call_id=call_id).all()

        return jsonify({
            'success': True,
            'metrics': [m.to_dict() for m in metrics]
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
