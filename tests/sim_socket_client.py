import socketio
import time

sio = socketio.Client(logger=True, engineio_logger=True)

@sio.event
def connect():
    print('CLIENT: connected, sid=', sio.sid)
    # send register_user event (use an existing user id from DB, e.g., 1)
    try:
        sio.emit('register_user', {'user_id': 1})
        print('CLIENT: emitted register_user')
    except Exception as e:
        print('CLIENT: emit error', e)
    # wait a bit then disconnect
    time.sleep(1)
    sio.disconnect()

@sio.event
def disconnect():
    print('CLIENT: disconnected')

@sio.on('registered')
def on_registered(data):
    print('CLIENT: registered ack', data)

if __name__ == '__main__':
    try:
        sio.connect('http://localhost:5000', transports=['websocket'])
        # keep alive briefly to receive events
        time.sleep(2)
    except Exception as e:
        print('CLIENT: connection failed:', e)
