import types
import app
from types import SimpleNamespace
from datetime import datetime, timezone


def test_on_notification_insert_emits_unread_count(monkeypatch):
    emitted = []
    def fake_emit(event, payload, room=None):
        emitted.append((event, payload, room))

    # Patch socketio.emit
    monkeypatch.setattr(app, 'socketio', SimpleNamespace(emit=fake_emit))

    # Patch Notification.query.filter_by(...).count() to return a known value
    class DummyQuery:
        def filter_by(self, **kwargs):
            class Q:
                def count(self):
                    return 5
            return Q()

    class DummyNotification:
        query = DummyQuery()

    monkeypatch.setattr(app, 'Notification', DummyNotification)

    target = SimpleNamespace(
        id=123,
        notification_type='message',
        title='Hello',
        body='You have a message',
        sender_id=2,
        appointment_id=None,
        is_read=False,
        created_at=datetime.now(timezone.utc),
        user_id=42
    )

    # Call the listener
    app._on_notification_insert(None, None, target)

    # Ensure unread_count emit present
    assert any(call[0] == 'unread_count' for call in emitted), "unread_count was not emitted"
