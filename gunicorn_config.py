"""
Gunicorn configuration for Netbox Helper production deployment.

Usage:
    gunicorn -c gunicorn_config.py netbox_helper:app
    
Or with environment variables:
    PORT=443 gunicorn -c gunicorn_config.py netbox_helper:app

Environment Variables:
    PORT              - Port to listen on (default: 8000)
    GUNICORN_BIND     - Full bind address (default: 127.0.0.1:<PORT>)
    GUNICORN_WORKERS  - Number of worker processes (default: 1)
    GUNICORN_THREADS  - Threads per worker (default: 2)
    GUNICORN_TIMEOUT  - Worker timeout in seconds (default: 120)
    GUNICORN_MAX_REQUESTS - Max requests before worker restart (default: 1000)
"""

import os
import json
# Server socket configuration
port = os.getenv('PORT', '8000')
bind = os.getenv('GUNICORN_BIND', f"127.0.0.1:{port}")
backlog = 2048

# Worker processes
#
# IMPORTANT:
# CSV import queue state is in-process memory. Running multiple Gunicorn workers
# causes each worker to have a different queue, leading to "No pending jobs" and
# inconsistent queue views. Keep workers=1 unless queue storage is externalized.
workers = int(os.getenv('GUNICORN_WORKERS', 1))
worker_class = "sync"  # Use sync workers (compatible with Flask)
threads = int(os.getenv('GUNICORN_THREADS', 2))
worker_connections = 1000
timeout = int(os.getenv('GUNICORN_TIMEOUT', 120))
keepalive = 5
max_requests = int(os.getenv('GUNICORN_MAX_REQUESTS', 1000))
max_requests_jitter = 50

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Logging
accesslog = 'logs/gunicorn-access.log'
errorlog = 'logs/gunicorn-error.log'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'netbox-helper'

# SSL Configuration
# These can be overridden with environment variables or command line:
#   gunicorn -c gunicorn_config.py \
#     --certfile=/path/to/cert.pem \
#     --keyfile=/path/to/key.pem \
#     netbox_helper:app

# First, try to load from settings.json
ssl_enabled = False
cert_file = ''
key_file = ''

settings_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.json')
if os.path.exists(settings_file):
    try:
        with open(settings_file, 'r') as f:
            settings = json.load(f)
            ssl_config = settings.get('ssl', {})
            if isinstance(ssl_config, dict):
                ssl_enabled = ssl_config.get('enabled', False)
                cert_file = str(ssl_config.get('certfile', '') or '').strip()
                key_file = str(ssl_config.get('keyfile', '') or '').strip()
    except Exception as e:
        print(f'Warning: Could not load SSL config from settings.json: {e}')

# Environment variables override settings.json
env_enabled = os.getenv('NBH_SSL_ENABLED', '').strip().lower()
if env_enabled in ('1', 'true', 'yes', 'on'):
    ssl_enabled = True
elif env_enabled in ('0', 'false', 'no', 'off'):
    ssl_enabled = False

env_cert = os.getenv('NBH_SSL_CERTFILE', '').strip()
if env_cert:
    cert_file = env_cert

env_key = os.getenv('NBH_SSL_KEYFILE', '').strip()
if env_key:
    key_file = env_key

# Apply SSL configuration to Gunicorn
if ssl_enabled:
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        certfile = cert_file
        keyfile = key_file
        print(f'SSL enabled: certfile={cert_file}, keyfile={key_file}')
    else:
        # SSL enabled but files not found - log warning but continue
        print(f'WARNING: SSL enabled but certificate files not found or not configured')
        print(f'  Expected: certfile={cert_file}, keyfile={key_file}')

# Server hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    os.makedirs('logs', exist_ok=True)
    print(f'Starting Netbox Helper (Gunicorn) on {bind}')
    if workers > 1:
        print(
            'WARNING: GUNICORN_WORKERS > 1 is not supported for the in-memory import queue. '
            'Set GUNICORN_WORKERS=1 to avoid queue inconsistency.'
        )

def when_ready(server):
    """Called just after the server is started."""
    print('Gunicorn server is ready. Spawning workers')

def on_exit(server):
    """Called just before exiting Gunicorn."""
    print('Shutting down Netbox Helper')

def worker_abort(worker):
    """Called when a worker receives the SIGABRT signal."""
    print(f'Worker {worker.pid} aborted')

def post_worker_init(worker):
    """Called just after a worker has initialized."""
    print(f'Worker spawned (pid: {worker.pid})')
