import os
import threading
import time
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for, send_file
from werkzeug.utils import secure_filename
from netbox_importer import NetboxImporter, ImportStopped, resolve_instance
import logging
import csv
import json
from collections import defaultdict
from functools import wraps
from dotenv import load_dotenv
from glitchtip_utils import init_glitchtip, capture_exception

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key_if_none')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)

init_glitchtip(service='netbox-app-legacy', with_flask=True)

# Authentication credentials from .env
APP_USERNAME = os.getenv('APP_USERNAME', 'admin')
APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin')
APP_ICON_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Icon.png')

# ---------------------------------------------------------------------------
# Job Queue State
# ---------------------------------------------------------------------------
# Each job dict:
#   id          : str (uuid4 short)
#   file_path   : str
#   filename    : str (display name)
#   dry_run     : bool
#   replace     : bool
#   sections    : list|None
#   delay       : float
#   status      : 'pending' | 'running' | 'done' | 'failed' | 'stopped'
#   log_file    : str  (path to per-job log)
#   start_time  : float|None
#   end_time    : float|None
#   error       : str|None

job_queue = []          # ordered list of job dicts
queue_lock = threading.Lock()
stop_requested = False  # signal to stop the *current* running job
worker_running = False  # True while the background worker loop is alive
worker_thread = None
worker_state_lock = threading.Lock()

# Legacy compatibility — used by /status endpoint and stream-logs
import_status = {
    'running': False,
    'last_file': None,
    'last_server_id': None,
    'start_time': None,
    'stop_requested': False,
    'stopped': False,
}


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def resolve_target_instance(server_id=None):
    """Resolve a NetBox target from instances.json. Defaults to the first instance."""
    inst = resolve_instance(instance_id=server_id) if server_id else resolve_instance()
    url = (inst.get('url') or '').strip().rstrip('/')
    token = (inst.get('token') or '').strip()
    if not url or not token:
        raise ValueError(f'Instance "{inst.get("name", "unknown")}" is missing URL or token')
    inst['url'] = url
    inst['token'] = token
    return inst


# ---------------------------------------------------------------------------
# Worker helpers
# ---------------------------------------------------------------------------

def _log_to_job(job, message):
    """Append a timestamped line to the job's dedicated log file."""
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(job['log_file'], 'a', encoding='utf-8') as f:
        f.write(f"[{ts}] {message}\n")


def _run_single_job(job):
    """Execute one import job. Called from the worker thread."""
    global stop_requested, import_status

    log_path = job['log_file']
    file_path = job['file_path']
    dry_run = job['dry_run']
    replace = job['replace']
    sections = job['sections']
    delay = job['delay']
    workers = job.get('workers', 4)

    # Write job header directly (before FileHandler is attached)
    header_parts = [f"--- Job {job['id']}: {job['filename']} ({'Dry Run' if dry_run else 'Live'}) ---"]
    if delay > 0:
        header_parts.append(f"Slow Mode: {delay}s delay")
    elif workers > 1:
        header_parts.append(f"Workers: {workers}")
    if sections:
        header_parts.append(f"Sections: {', '.join(sections)}")
    header = '\n'.join(header_parts)

    _log_to_job(job, header)

    # Mirror header to legacy log (overwrite) so /stream-logs picks it up
    with open('netbox_import.log', 'w', encoding='utf-8') as f:
        f.write(header + '\n')

    # Attach a FileHandler so all logger.info/error output goes to the per-job log with timestamps
    job_handler = logging.FileHandler(log_path, encoding='utf-8')
    job_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root_logger = logging.getLogger()
    root_logger.addHandler(job_handler)

    import_status['running'] = True
    import_status['stop_requested'] = False
    import_status['stopped'] = False
    import_status['start_time'] = job['start_time']
    import_status['last_file'] = file_path
    stop_requested = False

    def check_stop():
        return stop_requested

    try:
        srv = resolve_target_instance(job.get('server_id'))
        import_status['last_server_id'] = srv.get('id')
        _log_to_job(job, f"Target server: {srv.get('name', 'default')} ({srv['url']})")

        importer = NetboxImporter(
            file_path,
            dry_run=dry_run,
            replace=replace,
            interactive=False,
            netbox_url=srv['url'],
            netbox_token=srv['token'],
            netbox_skip_ssl_verify=bool(srv.get('skip_ssl_verify', False)),
        )
        data = importer.parse_csv()
        importer.import_data(data, sections=sections, should_stop=check_stop, delay=delay, workers=workers)
        job['status'] = 'done'
    except ImportStopped:
        msg = "--- IMPORT STOPPED BY USER ---"
        with open('netbox_import.log', 'a') as f:
            f.write(msg + '\n')
        _log_to_job(job, msg)
        job['status'] = 'stopped'
        import_status['stopped'] = True
    except Exception as e:
        msg = f"FATAL ERROR: {str(e)}"
        with open('netbox_import.log', 'a') as f:
            f.write(msg + '\n')
        _log_to_job(job, msg)
        capture_exception(
            e,
            route='legacy_csv_import_worker',
            job_id=job.get('id'),
            filename=job.get('filename'),
            server_id=job.get('server_id'),
        )
        job['status'] = 'failed'
        job['error'] = str(e)
    finally:
        root_logger.removeHandler(job_handler)
        job_handler.close()
        job['end_time'] = time.time()
        import_status['running'] = False


def _worker_loop():
    """Background thread: processes pending jobs one at a time."""
    global worker_running, worker_thread
    try:
        while True:
            job = None
            with queue_lock:
                for j in job_queue:
                    if j['status'] == 'pending':
                        j['status'] = 'running'
                        j['start_time'] = time.time()
                        job = j
                        break

            if job is None:
                # No pending jobs — worker exits; will be restarted on next enqueue
                break

            _run_single_job(job)

            # If the job was stopped by user, pause queue (don't auto-continue)
            if job['status'] == 'stopped':
                break
    finally:
        with worker_state_lock:
            worker_running = False
            worker_thread = None


def _ensure_worker():
    """Start the worker thread if it isn't already running."""
    global worker_running, worker_thread
    with worker_state_lock:
        if worker_thread is not None and worker_thread.is_alive():
            worker_running = True
            return
        t = threading.Thread(target=_worker_loop, daemon=True)
        worker_thread = t
        worker_running = True
        t.start()


# ---------------------------------------------------------------------------
# Retry helper (kept from original)
# ---------------------------------------------------------------------------

def run_retry_thread(file_path, dry_run, replace, delay=0.0, server_id=None):
    global import_status, stop_requested

    import_status['running'] = True
    import_status['stop_requested'] = False
    import_status['stopped'] = False
    import_status['start_time'] = time.time()
    stop_requested = False

    def check_stop():
        return stop_requested

    try:
        failed_records = []
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'original_data' in row:
                        try:
                            original_row = json.loads(row['original_data'])
                            failed_records.append((row['import_type'], original_row))
                        except json.JSONDecodeError:
                            continue

        if os.path.exists(file_path):
            os.remove(file_path)

        data = defaultdict(list)
        for import_type, row in failed_records:
            data[import_type].append(row)

        srv = resolve_target_instance(server_id)
        importer = NetboxImporter(
            "failures.csv",
            dry_run=dry_run,
            replace=replace,
            interactive=False,
            netbox_url=srv['url'],
            netbox_token=srv['token'],
            netbox_skip_ssl_verify=bool(srv.get('skip_ssl_verify', False)),
        )
        importer.import_data(data, should_stop=check_stop, delay=delay)

    except ImportStopped:
        with open('netbox_import.log', 'a') as f:
            f.write("\n--- RETRY STOPPED BY USER ---\n")
        import_status['stopped'] = True
    except Exception as e:
        with open('netbox_import.log', 'a') as f:
            f.write(f"\nFATAL ERROR IN RETRY THREAD: {str(e)}\n")
        capture_exception(
            e,
            route='legacy_retry_failures_worker',
            server_id=server_id,
            filename=file_path,
        )
    finally:
        import_status['running'] = False


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == APP_USERNAME and request.form['password'] == APP_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/app-icon.png')
def app_icon():
    if os.path.exists(APP_ICON_FILE):
        return send_file(APP_ICON_FILE, mimetype='image/png')
    return '', 404


@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('app_icon'))


@app.route('/')
@login_required
def index():
    return render_template('index.html')


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        import_status['last_file'] = path
        import_status['stopped'] = False
        return jsonify({'message': f'File {filename} uploaded successfully', 'path': path, 'filename': filename})
    return jsonify({'error': 'Invalid file type. Please upload a CSV.'}), 400


# ---------------------------------------------------------------------------
# Queue endpoints
# ---------------------------------------------------------------------------

@app.route('/queue', methods=['GET'])
@login_required
def get_queue():
    with queue_lock:
        result = []
        for j in job_queue:
            result.append({
                'id': j['id'],
                'filename': j['filename'],
                'dry_run': j['dry_run'],
                'replace': j['replace'],
                'sections': j['sections'],
                'delay': j['delay'],
                'workers': j.get('workers', 4),
                'server_id': j.get('server_id'),
                'status': j['status'],
                'start_time': j['start_time'],
                'end_time': j['end_time'],
                'error': j['error'],
            })
    return jsonify({'queue': result, 'worker_running': worker_running})


@app.route('/queue', methods=['POST'])
@login_required
def enqueue_job():
    data = request.json or {}
    file_path = data.get('file_path')
    filename = data.get('filename') or os.path.basename(file_path or '')

    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 400

    job_id = uuid.uuid4().hex[:8]
    log_file = os.path.join('logs', f'job_{job_id}.log')

    job = {
        'id': job_id,
        'file_path': file_path,
        'filename': filename,
        'dry_run': bool(data.get('dry_run', False)),
        'replace': bool(data.get('replace', False)),
        'sections': data.get('sections') or None,
        'delay': float(data.get('delay', 0.0)),
        'workers': int(data.get('workers', 4)),
        'server_id': data.get('server_id') or None,
        'status': 'pending',
        'log_file': log_file,
        'start_time': None,
        'end_time': None,
        'error': None,
    }

    with queue_lock:
        job_queue.append(job)

    return jsonify({'message': 'Job added to queue', 'job_id': job_id})


@app.route('/queue/start', methods=['POST'])
@login_required
def start_queue():
    """Start processing pending jobs in the queue."""
    if import_status['running']:
        return jsonify({'error': 'An import is already running'}), 400

    has_pending = any(j['status'] == 'pending' for j in job_queue)
    if not has_pending:
        return jsonify({'error': 'No pending jobs in the queue'}), 400

    _ensure_worker()
    return jsonify({'message': 'Queue started'})


@app.route('/queue/<job_id>/remove', methods=['POST'])
@login_required
def remove_job(job_id):
    with queue_lock:
        for i, j in enumerate(job_queue):
            if j['id'] == job_id:
                if j['status'] == 'running':
                    return jsonify({'error': 'Cannot remove a running job'}), 400
                job_queue.pop(i)
                return jsonify({'message': 'Job removed'})
    return jsonify({'error': 'Job not found'}), 404


@app.route('/queue/<job_id>/log', methods=['GET'])
@login_required
def get_job_log(job_id):
    with queue_lock:
        job = next((j for j in job_queue if j['id'] == job_id), None)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    log_path = job['log_file']
    if not os.path.exists(log_path):
        return jsonify({'log': ''})
    with open(log_path, 'r', encoding='utf-8') as f:
        return jsonify({'log': f.read()})


@app.route('/queue/clear', methods=['POST'])
@login_required
def clear_queue():
    """Remove all completed/failed/stopped jobs from the queue."""
    with queue_lock:
        finished = {'done', 'failed', 'stopped'}
        before = len(job_queue)
        job_queue[:] = [j for j in job_queue if j['status'] not in finished]
        removed = before - len(job_queue)
    return jsonify({'message': f'Cleared {removed} finished jobs'})


# ---------------------------------------------------------------------------
# Legacy start-import (single file, immediate) — kept for compatibility
# ---------------------------------------------------------------------------

@app.route('/start-import', methods=['POST'])
@login_required
def start_import():
    if import_status['running']:
        return jsonify({'error': 'An import is already in progress'}), 400

    data = request.json or {}
    dry_run = data.get('dry_run', False)
    replace = data.get('replace', False)
    sections = data.get('sections')
    server_id = data.get('server_id') or None
    file_path = data.get('file_path') or import_status['last_file']
    delay = float(data.get('delay', 0.0))

    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'No file available for import'}), 400

    # Create a one-off job and run it via the queue
    job_id = uuid.uuid4().hex[:8]
    log_file = os.path.join('logs', f'job_{job_id}.log')
    job = {
        'id': job_id,
        'file_path': file_path,
        'filename': os.path.basename(file_path),
        'dry_run': dry_run,
        'replace': replace,
        'sections': sections,
        'server_id': server_id,
        'delay': delay,
        'status': 'pending',
        'log_file': log_file,
        'start_time': None,
        'end_time': None,
        'error': None,
    }

    with open('netbox_import.log', 'w') as f:
        f.write(f"--- Starting Import ({'Dry Run' if dry_run else 'Live Run'}) ---\n")
        if delay > 0:
            f.write(f"Slow Mode Enabled: {delay}s delay\n")
        if sections:
            f.write(f"Selected sections: {', '.join(sections)}\n")

    with queue_lock:
        job_queue.append(job)

    _ensure_worker()
    return jsonify({'message': 'Import started'})


# ---------------------------------------------------------------------------
# Stop / Status / Sections (mostly unchanged)
# ---------------------------------------------------------------------------

@app.route('/stop-import', methods=['POST'])
@login_required
def stop_import():
    global stop_requested
    if not import_status['running']:
        return jsonify({'error': 'No import running'}), 400
    stop_requested = True
    import_status['stop_requested'] = True
    return jsonify({'message': 'Stop signal sent'})


@app.route('/get-sections', methods=['POST'])
@login_required
def get_sections():
    data = request.json or {}
    file_path = data.get('file_path') or import_status['last_file']

    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'No file available'}), 400

    try:
        importer = NetboxImporter(file_path, connect=False)
        parsed_data = importer.parse_csv()
        available = [s for s in importer.IMPORT_ORDER if s in parsed_data]
        return jsonify({'sections': available})
    except Exception as e:
        capture_exception(e, route='legacy_get_sections', filename=file_path)
        return jsonify({'error': str(e)}), 500


@app.route('/retry-failures', methods=['POST'])
@login_required
def retry_failures():
    if import_status['running']:
        return jsonify({'error': 'An import is already in progress'}), 400

    file_path = 'failures.csv'
    if not os.path.exists(file_path):
        return jsonify({'error': 'No failures to retry'}), 400

    data = request.json or {}
    dry_run = data.get('dry_run', False)
    replace = data.get('replace', False)
    delay = float(data.get('delay', 0.0))
    server_id = data.get('server_id') or import_status.get('last_server_id')

    with open('netbox_import.log', 'w') as f:
        f.write(f"--- Starting Retry of Failures ({'Dry Run' if dry_run else 'Live Run'}) ---\n")
        if delay > 0:
            f.write(f"Slow Mode Enabled: {delay}s delay\n")

    thread = threading.Thread(target=run_retry_thread, args=(file_path, dry_run, replace, delay, server_id))
    thread.start()
    return jsonify({'message': 'Retry started'})


@app.route('/clear-failures', methods=['POST'])
@login_required
def clear_failures():
    file_path = 'failures.csv'
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return jsonify({'message': 'Failures cleared'})
        except Exception as e:
            capture_exception(e, route='legacy_clear_failures')
            return jsonify({'error': str(e)}), 500
    return jsonify({'message': 'No failures to clear'})


@app.route('/status')
@login_required
def get_status():
    status = import_status.copy()
    status['has_failures'] = os.path.exists('failures.csv')
    return jsonify(status)


# ---------------------------------------------------------------------------
# Log streaming (streams the legacy netbox_import.log — current running job)
# ---------------------------------------------------------------------------

@app.route('/stream-logs')
@login_required
def stream_logs():
    def generate():
        log_path = 'netbox_import.log'
        if not os.path.exists(log_path):
            with open(log_path, 'w') as f:
                f.write("Log file initialized.\n")

        with open(log_path, 'r') as f:
            while True:
                line = f.readline()
                if line:
                    yield f"data: {line}\n\n"
                else:
                    if not import_status['running']:
                        time.sleep(1)
                        line = f.readline()
                        if line:
                            yield f"data: {line}\n\n"
                        if import_status['stopped']:
                            yield "data: [STOPPED]\n\n"
                        else:
                            yield "data: [DONE]\n\n"
                        break
                    time.sleep(0.1)

    return Response(generate(), mimetype='text/event-stream')


if __name__ == '__main__':
    port = int(os.getenv('PORT', 81))
    
    # Configure SSL support (legacy app.py uses environment variables only)
    # Set NBH_SSL_ENABLED=true, NBH_SSL_CERTFILE=/path/to/cert.pem, NBH_SSL_KEYFILE=/path/to/key.pem
    ssl_enabled = str(os.getenv('NBH_SSL_ENABLED', '') or '').strip().lower() in ('1', 'true', 'yes', 'on')
    ssl_context = None
    
    if ssl_enabled:
        certfile = str(os.getenv('NBH_SSL_CERTFILE', '') or '').strip()
        keyfile = str(os.getenv('NBH_SSL_KEYFILE', '') or '').strip()
        
        if not certfile or not keyfile:
            raise RuntimeError('SSL enabled but NBH_SSL_CERTFILE or NBH_SSL_KEYFILE not configured')
        
        if not os.path.exists(certfile) or not os.path.exists(keyfile):
            raise RuntimeError(f'SSL certificate files not found: certfile={certfile}, keyfile={keyfile}')
        
        ssl_context = (certfile, keyfile)
        app.logger.info('Starting HTTPS (legacy) on 0.0.0.0:%d', port)
        app.run(host='0.0.0.0', port=port, debug=False, ssl_context=ssl_context)
    else:
        app.run(host='0.0.0.0', port=port, debug=False)
