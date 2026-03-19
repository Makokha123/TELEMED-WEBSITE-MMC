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
        for apt in Appointment.query.order_by(Appointment.id.desc()).limit(200).all():
            doctor = db.session.get(Doctor, apt.doctor_id) if apt.doctor_id else None
            patient = db.session.get(Patient, apt.patient_id) if apt.patient_id else None
            doctor_user = db.session.get(User, doctor.user_id) if doctor and doctor.user_id else None
            patient_user = db.session.get(User, patient.user_id) if patient and patient.user_id else None
            if not doctor_user or not patient_user:
                continue
            try:
                allowed, _reason = can_patient_access_messaging(apt.id, patient_user)
            except Exception:
                allowed = False
            if allowed:
                return apt.id, doctor_user.id, patient_user.id, True

        for apt in Appointment.query.order_by(Appointment.id.desc()).limit(200).all():
            doctor = db.session.get(Doctor, apt.doctor_id) if apt.doctor_id else None
            patient = db.session.get(Patient, apt.patient_id) if apt.patient_id else None
            doctor_user = db.session.get(User, doctor.user_id) if doctor and doctor.user_id else None
            patient_user = db.session.get(User, patient.user_id) if patient and patient.user_id else None
            if doctor_user and patient_user:
                return apt.id, doctor_user.id, patient_user.id, False

    raise RuntimeError('No usable appointment with doctor/patient users found')


def main():
    report = {
        'setup': {},
        'api': {},
        'socket': {},
        'errors': [],
    }

    appointment_id, doctor_user_id, patient_user_id, payment_ok = pick_appointment()
    report['setup'] = {
        'appointment_id': appointment_id,
        'doctor_user_id': doctor_user_id,
        'patient_user_id': patient_user_id,
        'patient_payment_gate_open': payment_ok,
    }

    client_doc = app.test_client()
    login_client(client_doc, doctor_user_id)

    t0 = time.perf_counter()
    res1 = client_doc.get('/api/appointments')
    report['api']['appointments_status'] = res1.status_code
    report['api']['appointments_ms'] = round((time.perf_counter() - t0) * 1000, 2)
    appointments_payload = res1.get_json(silent=True)
    report['api']['appointments_count'] = len(appointments_payload) if isinstance(appointments_payload, list) else None

    t1 = time.perf_counter()
    res2 = client_doc.get(f'/api/appointment/{appointment_id}/messages?page=1&per_page=100')
    report['api']['messages_status'] = res2.status_code
    report['api']['messages_ms'] = round((time.perf_counter() - t1) * 1000, 2)
    messages_payload = res2.get_json(silent=True) or {}
    report['api']['messages_count'] = messages_payload.get('count') if isinstance(messages_payload, dict) else None
    report['api']['messages_has_more'] = messages_payload.get('has_more') if isinstance(messages_payload, dict) else None

    client_pat = app.test_client()
    login_client(client_pat, patient_user_id)

    original_message_queue = socketio.server_options.get('message_queue')
    socketio.server_options['message_queue'] = None

    s_doc = socketio.test_client(app, flask_test_client=client_doc)
    s_pat = socketio.test_client(app, flask_test_client=client_pat)

    report['socket']['doctor_connected'] = s_doc.is_connected()
    report['socket']['patient_connected'] = s_pat.is_connected()
    if not (s_doc.is_connected() and s_pat.is_connected()):
        report['errors'].append('socket_clients_not_connected')

    s_doc.emit('join_appointment', {'appointment_id': appointment_id})
    s_pat.emit('join_appointment', {'appointment_id': appointment_id})

    _ = s_doc.get_received()
    patient_join_events = s_pat.get_received()
    join_errors = [ev for ev in patient_join_events if ev.get('name') == 'error']
    report['socket']['patient_join_error'] = bool(join_errors)
    if join_errors:
        report['socket']['patient_join_error_payload'] = join_errors

    content = f"SMOKE_{int(time.time())}"
    client_msg_id = f"smoke-{int(time.time() * 1000)}"

    with app.app_context():
        pre_count = Communication.query.filter_by(appointment_id=appointment_id).count()
    report['socket']['db_message_count_before'] = pre_count

    send_start = time.perf_counter()
    s_doc.emit(
        'send_message',
        {
            'appointment_id': appointment_id,
            'content': content,
            'message_type': 'text',
            'client_msg_id': client_msg_id,
        },
    )

    recv_payload = None
    recv_ms = None
    send_errors = []
    send_acks = []
    for _ in range(100):
        pat_events = s_pat.get_received()
        doc_events = s_doc.get_received()

        for ev in doc_events:
            if ev.get('name') == 'message_error':
                send_errors.append(ev)
            if ev.get('name') == 'message_ack':
                send_acks.append(ev)
            if ev.get('name') == 'message_received' and recv_payload is None:
                args = ev.get('args') or []
                payload = args[0] if args and isinstance(args[0], dict) else {}
                if payload.get('content') == content:
                    recv_payload = payload
                    recv_ms = (time.perf_counter() - send_start) * 1000

        for ev in pat_events:
            if ev.get('name') == 'message_received':
                args = ev.get('args') or []
                payload = args[0] if args and isinstance(args[0], dict) else {}
                if payload.get('content') == content:
                    recv_payload = payload
                    recv_ms = (time.perf_counter() - send_start) * 1000
                    break
        if recv_payload:
            break
        time.sleep(0.1)

    report['socket']['send_error'] = bool(send_errors)
    if send_errors:
        report['socket']['send_error_payload'] = send_errors
    report['socket']['send_ack'] = bool(send_acks)
    if send_acks:
        report['socket']['send_ack_payload'] = send_acks

    report['socket']['message_received'] = bool(recv_payload)
    report['socket']['message_received_ms'] = round(recv_ms, 2) if recv_ms is not None else None

    sent_message_id = recv_payload.get('id') if isinstance(recv_payload, dict) else None
    report['socket']['sent_message_id'] = sent_message_id

    delivery_seen = False
    delivery_payload = None
    for _ in range(10):
        doc_events = s_doc.get_received()
        for ev in doc_events:
            if ev.get('name') == 'message_status_updated':
                args = ev.get('args') or []
                payload = args[0] if args and isinstance(args[0], dict) else {}
                if payload.get('status') == 'delivered' and (
                    sent_message_id is None or payload.get('message_id') == sent_message_id
                ):
                    delivery_seen = True
                    delivery_payload = payload
                    break
        if delivery_seen:
            break
        time.sleep(0.05)

    report['socket']['delivery_status_event'] = delivery_seen
    if delivery_payload:
        report['socket']['delivery_payload'] = delivery_payload

    read_seen = False
    read_ms = None
    if sent_message_id is not None:
        read_start = time.perf_counter()
        s_pat.emit('message_read', {'appointment_id': appointment_id, 'message_id': sent_message_id})
        for _ in range(40):
            doc_events = s_doc.get_received()
            for ev in doc_events:
                if ev.get('name') == 'message_read':
                    args = ev.get('args') or []
                    payload = args[0] if args and isinstance(args[0], dict) else {}
                    if payload.get('message_id') == sent_message_id:
                        read_seen = True
                        read_ms = (time.perf_counter() - read_start) * 1000
                        break
            if read_seen:
                break
            time.sleep(0.05)

    report['socket']['message_read_event'] = read_seen
    report['socket']['message_read_ms'] = round(read_ms, 2) if read_ms is not None else None

    with app.app_context():
        post_count = Communication.query.filter_by(appointment_id=appointment_id).count()
        persisted = Communication.query.filter(
            Communication.appointment_id == appointment_id,
            Communication.content == content,
        ).order_by(Communication.id.desc()).first()
    report['socket']['db_message_count_after'] = post_count
    report['socket']['db_message_persisted'] = persisted is not None
    if persisted is not None:
        report['socket']['db_persisted_message_id'] = persisted.id

    s_doc.disconnect()
    s_pat.disconnect()
    socketio.server_options['message_queue'] = original_message_queue

    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
