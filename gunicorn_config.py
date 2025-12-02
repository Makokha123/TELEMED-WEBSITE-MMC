import multiprocessing

# Worker configuration
workers = 1  # Reduce workers for Render
worker_class = 'eventlet'  # Use eventlet for Socket.IO
worker_connections = 1000
timeout = 120  # Increase timeout
keepalive = 5

# Socket configuration
bind = '0.0.0.0:5000'

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Process naming
proc_name = 'telemed_websocket_server'