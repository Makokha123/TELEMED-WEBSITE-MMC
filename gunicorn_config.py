# gunicorn_config.py
import multiprocessing

# Worker configuration
workers = 1  # Use only 1 worker on Render
worker_class = 'eventlet'
worker_connections = 1000
timeout = 300  # Increase timeout for WebSocket connections
keepalive = 5

# Socket configuration
bind = '0.0.0.0:10000'  # Use port 10000 for Render

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Process naming
proc_name = 'telemed_websocket_server'

# Eventlet specific settings
max_requests = 1000
max_requests_jitter = 50