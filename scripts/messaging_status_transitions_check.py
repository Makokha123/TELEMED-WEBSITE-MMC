import json
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ['REDIS_URL'] = ''
os.environ['SOCKETIO_REDIS_URL'] = ''
os.environ['CELERY_BROKER_URL'] = ''

from app import (
    app,
    db,
    socketio,
    User,
    Doctor,
    Patient,
    Appointment,
    Communication,
    can_patient_access_messaging,
)


def login_client(flask_client, user_id):
    with flask_client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True


def pick_appointment():
    with app.app_context():
        for apt in Appointment.query.order_by(Appointment.id.desc()).limit(300).all():
            doctor = db.session.get(Doctor, apt.doctor_id) if apt.doctor_id else None
            patient = db.session.get(Patient, apt.patient_id) if apt.patient_id else None
            doctor_user = db.session.get(User, doctor.user_id) if doctor and doctor.user_id else None
            patient_user = db.session.get(User, patient.user_id) if patient and patient.user_id else None
            if not doctor_user or not patient_user:
                continue
            try:
                allowed, _ = can_patient_access_messaging(apt.id, patient_user)
            except Exception:
                allowed = False
            if allowed:
                return apt.id, doctor_user.id, patient_user.id

        for apt in Appointment.query.order_by(Appointment.id.desc()).limit(300).all():
            doctor = db.session.get(Doctor, apt.doctor_id) if apt.doctor_id else None
            patient = db.session.get(Patient, apt.patient_id) if apt.patient_id else None
            doctor_user = db.session.get(User, doctor.user_id) if doctor and doctor.user_id else None
            patient_user = db.session.get(User, patient.user_id) if patient and patient.user_id else None
            if doctor_user and patient_user:
                return apt.id, doctor_user.id, patient_user.id

    raise RuntimeError('No usable appointment with doctor/patient users found')


def poll_for_event(socket_client, event_names, predicate=None, timeout_s=6.0, sleep_s=0.05):
    start = time.perf_counter()
    names = set(event_names)
    while (time.perf_counter() - start) < timeout_s:
        events = socket_client.get_received()
        for ev in events:
            if ev.get('name') not in names:
                continue
            args = ev.get('args') or []
            payload = args[0] if args and isinstance(args[0], dict) else {}
            if predicate is None or predicate(ev.get('name'), payload):
                return True, ev.get('name'), payload
        time.sleep(sleep_s)
    return False, None, None


def transition_result(passed, details=None):
    return {
        'result': 'PASS' if passed else 'FAIL',
        'passed': bool(passed),
        'details': details or {}
    }


def main():
    report = {
        'setup': {},
        'transitions': {
            'Failed->Sent': transition_result(False),
            'Sent->Delivered': transition_result(False),
            'Delivered->Read': transition_result(False),
        },
        'artifacts': {},
        'errors': [],
    }

    appointment_id, doctor_user_id, patient_user_id = pick_appointment()
    report['setup'] = {
        'appointment_id': appointment_id,
        'doctor_user_id': doctor_user_id,
        'patient_user_id': patient_user_id,
    }

    doc_http = app.test_client()
    pat_http = app.test_client()
    login_client(doc_http, doctor_user_id)
    login_client(pat_http, patient_user_id)

    original_message_queue = socketio.server_options.get('message_queue')
    socketio.server_options['message_queue'] = None

    s_doc = None
    s_pat = None

    try:
        s_doc = socketio.test_client(app, flask_test_client=doc_http)
        s_pat = socketio.test_client(app, flask_test_client=pat_http)

        if not (s_doc.is_connected() and s_pat.is_connected()):
            report['errors'].append('socket_clients_not_connected')
            print(json.dumps(report, indent=2))
            return

        s_doc.emit('join_appointment', {'appointment_id': appointment_id})
        s_pat.emit('join_appointment', {'appointment_id': appointment_id})
        _ = s_doc.get_received()
        _ = s_pat.get_received()

        content = f"STATUS_TRANSITION_{int(time.time())}"
        client_msg_id = f"status-transition-{int(time.time() * 1000)}"

        with app.app_context():
            before_count = Communication.query.filter_by(appointment_id=appointment_id).count()
            before_max_id = db.session.query(db.func.max(Communication.id)).filter(
                Communication.appointment_id == appointment_id
            ).scalar() or 0

        # --- Transition 1: Failed -> Sent (simulated network down then resend) ---
        s_doc.disconnect()
        failed_condition = not s_doc.is_connected()

        disconnected_emit_error = None
        try:
            s_doc.emit('send_message', {
                'appointment_id': appointment_id,
                'content': f"{content}_offline_attempt",
                'message_type': 'text',
                'client_msg_id': f"{client_msg_id}-offline",
            })
        except Exception as exc:
            disconnected_emit_error = str(exc)

        with app.app_context():
            after_offline_attempt_count = Communication.query.filter_by(appointment_id=appointment_id).count()

        # Reconnect sender and resend same logical message
        s_doc = socketio.test_client(app, flask_test_client=doc_http)
        reconnect_ok = s_doc.is_connected()
        if reconnect_ok:
            s_doc.emit('join_appointment', {'appointment_id': appointment_id})
            _ = s_doc.get_received()

        send_start = time.perf_counter()
        s_doc.emit('send_message', {
            'appointment_id': appointment_id,
            'content': content,
            'message_type': 'text',
            'client_msg_id': client_msg_id,
        })

        ack_ok, _, ack_payload = poll_for_event(
            s_doc,
            {'message_ack'},
            predicate=lambda _n, p: p.get('client_msg_id') == client_msg_id,
            timeout_s=4.0,
        )

        recv_ok, _, recv_payload = poll_for_event(
            s_pat,
            {'message_received'},
            predicate=lambda _n, p: p.get('content') == content,
            timeout_s=4.0,
        )

        message_id = None
        if isinstance(recv_payload, dict):
            message_id = recv_payload.get('id')
        if message_id is None and isinstance(ack_payload, dict):
            message_id = ack_payload.get('message_id')

        with app.app_context():
            after_online_send_count = Communication.query.filter_by(appointment_id=appointment_id).count()
            new_message = Communication.query.filter(
                Communication.appointment_id == appointment_id,
                Communication.id > before_max_id,
                Communication.sender_id == doctor_user_id,
            ).order_by(Communication.id.desc()).first()

        if message_id is None and new_message is not None:
            message_id = new_message.id

        failed_to_sent_pass = (
            failed_condition
            and reconnect_ok
            and (after_offline_attempt_count == before_count)
            and (after_online_send_count == before_count + 1)
            and bool(message_id)
        )
        report['transitions']['Failed->Sent'] = transition_result(
            failed_to_sent_pass,
            {
                'network_down_simulated': failed_condition,
                'offline_emit_exception': disconnected_emit_error,
                'reconnected': reconnect_ok,
                'message_ack_received': ack_ok,
                'receiver_got_message': recv_ok,
                'count_before': before_count,
                'count_after_offline_attempt': after_offline_attempt_count,
                'count_after_online_send': after_online_send_count,
                'before_max_message_id': before_max_id,
                'message_id': message_id,
                'message_found_by_db_delta': bool(new_message),
                'send_latency_ms': round((time.perf_counter() - send_start) * 1000, 2),
            },
        )

        if not message_id:
            report['errors'].append('message_id_missing_after_send')
        else:
            report['artifacts']['message_id'] = message_id
            report['artifacts']['content'] = content

            # --- Transition 2: Sent -> Delivered ---
            s_pat.emit('message_delivered', {'appointment_id': appointment_id, 'message_id': message_id})
            delivered_ok, delivered_event, delivered_payload = poll_for_event(
                s_doc,
                {'message_status_updated', 'message_receipt_updated'},
                predicate=lambda _n, p: p.get('message_id') == message_id and p.get('status') in ('delivered', 'read'),
                timeout_s=3.0,
            )

            delivered_db_status = None
            delivered_poll_start = time.perf_counter()
            while (time.perf_counter() - delivered_poll_start) < 6.0:
                with app.app_context():
                    persisted = db.session.get(Communication, message_id)
                    delivered_db_status = persisted.message_status if persisted else None
                if delivered_db_status in ('delivered', 'read'):
                    break
                time.sleep(0.1)

            sent_to_delivered_pass = delivered_db_status in ('delivered', 'read')
            report['transitions']['Sent->Delivered'] = transition_result(
                sent_to_delivered_pass,
                {
                    'delivered_event_seen': delivered_ok,
                    'delivered_event_name': delivered_event,
                    'delivered_payload': delivered_payload,
                    'db_message_status_after_delivery_check': delivered_db_status,
                },
            )

            # --- Transition 3: Delivered -> Read (final lock) ---
            s_pat.emit('message_read', {'appointment_id': appointment_id, 'message_id': message_id})

            read_ok, read_event, read_payload = poll_for_event(
                s_doc,
                {'message_read', 'message_status_updated', 'message_receipt_updated'},
                predicate=lambda _n, p: p.get('message_id') == message_id and (
                    (_n == 'message_read') or p.get('status') == 'read'
                ),
                timeout_s=8.0,
            )

            # Attempt to force a later delivered update; status should stay read
            s_pat.emit('message_delivered', {'appointment_id': appointment_id, 'message_id': message_id})
            time.sleep(0.2)

            final_status = None
            read_poll_start = time.perf_counter()
            while (time.perf_counter() - read_poll_start) < 6.0:
                with app.app_context():
                    persisted_after_read = db.session.get(Communication, message_id)
                    final_status = persisted_after_read.message_status if persisted_after_read else None
                if final_status == 'read':
                    break
                time.sleep(0.1)

            delivered_to_read_pass = read_ok and final_status == 'read'
            report['transitions']['Delivered->Read'] = transition_result(
                delivered_to_read_pass,
                {
                    'read_event_seen': read_ok,
                    'read_event_name': read_event,
                    'read_payload': read_payload,
                    'db_final_status': final_status,
                    'final_status_locked': final_status == 'read',
                },
            )

    except Exception as exc:
        report['errors'].append(str(exc))
    finally:
        try:
            if s_doc and s_doc.is_connected():
                s_doc.disconnect()
        except Exception:
            pass
        try:
            if s_pat and s_pat.is_connected():
                s_pat.disconnect()
        except Exception:
            pass
        socketio.server_options['message_queue'] = original_message_queue

    result_path = os.path.join(SCRIPT_DIR, 'messaging_status_transitions_result.json')
    try:
        with open(result_path, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2)
    except Exception as exc:
        report['errors'].append(f'failed_to_write_result_file: {exc}')

    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
