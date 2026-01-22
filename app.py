import atexit
import json
import logging
import os
import platform
import sys
import time
from datetime import datetime, timedelta

from flask import Flask, render_template, session
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from extensions import limiter
from services.storage import persist_audit_logs, load_known_issues, load_classroom_sync
from services.db import (
    init_db,
    get_engine,
    audit_logs_table,
    bug_reports_table,
    known_issues_table,
    login_logs_table
)
from services.google_admin import get_user_summary, READONLY_SCOPE, WRITE_SCOPE
from sqlalchemy import text, select, func
from sqlalchemy.engine import make_url
from auth import login_required, admin_required
from routes.auth import bp as auth_bp
from routes.main import bp as main_bp
from routes.admin import bp as admin_bp

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)
START_TIME = time.monotonic()

app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']
os.makedirs(os.path.join(app.root_path, 'data'), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

limiter.init_app(app)
init_db(app)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.context_processor
def inject_user():
    return {
        'user': session.get('user_info'),
        'role': session.get('role'),
        'theme': session.get('theme', 'light')
    }


app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(admin_bp)

def _format_timestamp(ts):
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return 'unknown'


@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/support')
def support_page():
    known_issues = load_known_issues()
    global_issues = [
        issue for issue in known_issues
        if issue.get('status') == 'Active' and issue.get('level') == 'global'
    ]
    support_issues = [
        issue for issue in known_issues
        if issue.get('status') == 'Active' and issue.get('level') == 'support'
    ]
    return render_template(
        'support.html',
        known_issues=known_issues,
        global_issues=global_issues,
        support_issues=support_issues
    )

@app.route('/report-bug')
@login_required
def report_bug_page():
    return redirect(url_for('main.report_bug'))


@app.route('/instructions')
@login_required
def instructions_page():
    return render_template('instructions.html', user=session.get('user_info'))


@app.route('/documentation')
@login_required
@admin_required
def documentation_page():
    return render_template('documentation.html', user=session.get('user_info'))


@app.route('/updates')
@login_required
def updates_page():
    return render_template('updates.html', user=session.get('user_info'), known_issues=load_known_issues())


@app.route('/status')
@login_required
@admin_required
def status_page():
    db_status = {'ok': False, 'detail': ''}
    db_details = []
    db_counts = []
    db_schema_time = 'unknown'
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text('SELECT 1'))
            tables = [
                ('audit_logs', audit_logs_table),
                ('bug_reports', bug_reports_table),
                ('known_issues', known_issues_table),
                ('login_logs', login_logs_table),
            ]
            for name, table in tables:
                count = conn.execute(
                    select(func.count()).select_from(table)
                ).scalar() or 0
                db_counts.append({'name': name, 'count': count})
        db_status['ok'] = True
        db_status['detail'] = 'Connected'
    except Exception as exc:
        db_status['detail'] = str(exc)

    google_status = {'ok': False, 'detail': ''}
    google_latency_ms = None
    google_token = {'ok': False, 'detail': ''}
    try:
        admin_user = app.config.get('ADMIN_USER')
        service_account_file = app.config.get('SERVICE_ACCOUNT_FILE')
        if not service_account_file:
            raise RuntimeError('SERVICE_ACCOUNT_FILE not set')
        if not admin_user:
            raise RuntimeError('ADMIN_USER not set')
        start = time.perf_counter()
        get_user_summary(admin_user)
        google_latency_ms = int((time.perf_counter() - start) * 1000)
        google_status['ok'] = True
        google_status['detail'] = 'Admin SDK OK'
    except Exception as exc:
        google_status['detail'] = str(exc)

    try:
        admin_user = app.config.get('ADMIN_USER')
        service_account_file = app.config.get('SERVICE_ACCOUNT_FILE')
        if not service_account_file:
            raise RuntimeError('SERVICE_ACCOUNT_FILE not set')
        if not os.path.isfile(service_account_file):
            raise RuntimeError('SERVICE_ACCOUNT_FILE missing on disk')
        if not admin_user:
            raise RuntimeError('ADMIN_USER not set')
        creds = service_account.Credentials.from_service_account_file(
            service_account_file,
            scopes=[READONLY_SCOPE]
        ).with_subject(admin_user)
        creds.refresh(Request())
        google_token['ok'] = True
        google_token['detail'] = 'Token refresh OK'
    except Exception as exc:
        google_token['detail'] = str(exc)

    sync_data = load_classroom_sync()
    last_sync = ''
    if sync_data:
        last_sync = max(
            (v.get('timestamp', '') for v in sync_data.values()),
            default=''
        )

    app_info = [
        {'name': 'Version', 'detail': os.environ.get('APP_VERSION', 'unknown')},
        {'name': 'Commit', 'detail': os.environ.get('GIT_SHA', 'unknown')},
        {'name': 'Build time', 'detail': os.environ.get('BUILD_TIME', 'unknown')},
        {'name': 'Python', 'detail': platform.python_version()},
    ]

    base_url = app.config.get('BASE_URL') or ''
    redirect_uri = app.config.get('REDIRECT_URI') or ''
    service_account_file = app.config.get('SERVICE_ACCOUNT_FILE') or ''
    config_checks = [
        {
            'name': 'BASE_URL',
            'detail': base_url or 'not set',
            'ok': bool(base_url),
        },
        {
            'name': 'REDIRECT_URI',
            'detail': redirect_uri or 'not set',
            'ok': bool(redirect_uri),
        },
        {
            'name': 'SERVICE_ACCOUNT_FILE',
            'detail': service_account_file or 'not set',
            'ok': bool(service_account_file) and os.path.isfile(service_account_file),
        },
        {
            'name': 'DEV_LOGIN_ENABLED',
            'detail': 'enabled' if app.config.get('DEV_LOGIN_ENABLED') else 'disabled',
            'ok': True,
        },
        {
            'name': 'SESSION_COOKIE_SECURE',
            'detail': 'true' if app.config.get('SESSION_COOKIE_SECURE') else 'false',
            'ok': app.config.get('SESSION_COOKIE_SECURE', False),
        },
    ]

    data_dir = os.path.join(app.root_path, 'data')
    upload_dir = app.config.get('UPLOAD_FOLDER')
    storage_checks = [
        {
            'name': 'Data directory writable',
            'detail': data_dir,
            'ok': os.path.isdir(data_dir) and os.access(data_dir, os.W_OK),
        },
        {
            'name': 'Upload directory writable',
            'detail': upload_dir,
            'ok': bool(upload_dir) and os.path.isdir(upload_dir) and os.access(upload_dir, os.W_OK),
        },
    ]
    json_files = [
        'admin_users.json',
        'global_admins.json',
        'reset_requests.json',
        'audit_logs.json',
        'bug_reports.json',
        'known_issues.json',
        'login_logs.json',
        'theme_preferences.json',
    ]
    for filename in json_files:
        path = os.path.join(app.root_path, filename)
        if not os.path.exists(path):
            storage_checks.append({
                'name': filename,
                'detail': 'missing',
                'ok': False,
            })
            continue
        try:
            with open(path, 'r', encoding='utf-8') as handle:
                json.load(handle)
            storage_checks.append({
                'name': filename,
                'detail': 'ok',
                'ok': True,
            })
        except Exception:
            storage_checks.append({
                'name': filename,
                'detail': 'invalid json',
                'ok': False,
            })

    db_url = app.config.get('DATABASE_URL', '')
    db_engine = 'unknown'
    db_location = 'unknown'
    try:
        if db_url:
            url = make_url(db_url)
            db_engine = url.get_backend_name() or 'unknown'
            if db_engine == 'sqlite':
                db_location = url.database or 'memory'
                if db_location and os.path.exists(db_location):
                    db_schema_time = _format_timestamp(os.path.getmtime(db_location))
            else:
                host = url.host or 'local'
                port = f":{url.port}" if url.port else ''
                name = url.database or ''
                db_location = f"{host}{port}/{name}" if name else f"{host}{port}"
    except Exception:
        db_engine = 'unknown'

    db_details = [
        {'name': 'Engine', 'detail': db_engine},
        {'name': 'Location', 'detail': db_location},
        {'name': 'Schema initialized', 'detail': db_schema_time},
    ]

    google_details = [
        {
            'name': 'Admin lookup latency',
            'detail': f"{google_latency_ms} ms" if google_latency_ms is not None else 'n/a',
            'ok': google_status['ok'],
        },
        {
            'name': 'Token refresh',
            'detail': google_token['detail'] or 'n/a',
            'ok': google_token['ok'],
        },
        {
            'name': 'Scopes',
            'detail': f"{READONLY_SCOPE}, {WRITE_SCOPE}",
            'ok': True,
        },
    ]

    uptime_seconds = max(0, int(time.monotonic() - START_TIME))
    runtime_details = [
        {'name': 'Uptime', 'detail': str(timedelta(seconds=uptime_seconds))},
        {
            'name': 'Workers',
            'detail': os.environ.get('WEB_CONCURRENCY')
            or os.environ.get('GUNICORN_WORKERS')
            or 'unknown',
        },
    ]
    try:
        import resource

        rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        memory_detail = f"{rss_kb / 1024:.1f} MB" if rss_kb else 'unknown'
    except Exception:
        memory_detail = 'unknown'
    runtime_details.append({'name': 'Memory (RSS)', 'detail': memory_detail})

    return render_template(
        'status.html',
        user=session.get('user_info'),
        db_status=db_status,
        google_status=google_status,
        classroom_sync_count=len(sync_data),
        classroom_last_sync=last_sync,
        app_info=app_info,
        config_checks=config_checks,
        storage_checks=storage_checks,
        db_details=db_details,
        db_counts=db_counts,
        google_details=google_details,
        runtime_details=runtime_details
    )


@app.errorhandler(403)
def forbidden(_):
    return render_template('403.html'), 403


@app.errorhandler(404)
def page_not_found(_):
    return render_template('404.html'), 404


def _persist_on_exit():
    with app.app_context():
        persist_audit_logs()

atexit.register(_persist_on_exit)


if __name__ == '__main__':
    ssl_context = 'adhoc' if app.config.get('USE_ADHOC_SSL') else None
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=ssl_context)
