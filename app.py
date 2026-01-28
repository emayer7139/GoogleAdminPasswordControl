import atexit
import json
import logging
import os
import platform
import secrets
import sys
import time
import subprocess
from datetime import datetime, timedelta

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from werkzeug.middleware.proxy_fix import ProxyFix

from auth import admin_required, login_required
from config import Config
from extensions import limiter
from routes.admin import bp as admin_bp
from routes.auth import bp as auth_bp
from routes.main import bp as main_bp
from services.db import (
    admin_users_table,
    audit_logs_table,
    bug_reports_table,
    classroom_sync_table,
    get_engine,
    global_admins_table,
    init_db,
    known_issues_table,
    login_logs_table,
    reset_requests_table,
    theme_preferences_table,
)
from services.emailer import send_email
from services.google_admin import READONLY_SCOPE, WRITE_SCOPE, get_user_summary
from services.storage import load_classroom_sync, load_known_issues, persist_audit_logs

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)
START_TIME = time.monotonic()
STATUS_NOTIFICATION_FILE = 'status_notifications.json'

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


def _run_git(args):
    try:
        return subprocess.check_output(
            ['git'] + list(args),
            cwd=app.root_path,
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
    except Exception:
        return ''


def _load_build_info_file():
    path = os.path.join(app.root_path, 'build_info.json')
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _get_build_metadata():
    cached = getattr(_get_build_metadata, '_cache', None)
    if cached:
        return cached

    file_info = _load_build_info_file()
    version = (os.environ.get('APP_VERSION') or file_info.get('version') or '').strip()
    commit = (os.environ.get('GIT_SHA') or file_info.get('commit') or '').strip()
    build_time = (os.environ.get('BUILD_TIME') or file_info.get('build_time') or '').strip()

    if not commit:
        commit = _run_git(['rev-parse', 'HEAD'])
    if not version:
        version = _run_git(['describe', '--tags', '--always', '--dirty'])
        if not version and commit:
            version = commit[:7]
    if not build_time:
        build_time = _run_git(['show', '-s', '--format=%cI', 'HEAD'])
    if not build_time:
        try:
            build_time = datetime.utcfromtimestamp(
                os.path.getmtime(__file__)
            ).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            build_time = ''

    info = {
        'version': version or 'unknown',
        'commit': commit or 'unknown',
        'build_time': build_time or 'unknown',
    }
    _get_build_metadata._cache = info
    return info


def _check_writable_dir(path):
    if not path:
        return False, 'not set'
    try:
        os.makedirs(path, exist_ok=True)
        probe_path = os.path.join(path, '.write_test')
        with open(probe_path, 'w', encoding='utf-8') as handle:
            handle.write('ok')
        os.remove(probe_path)
        return True, path
    except Exception as exc:
        return False, f"{path} ({exc})"


def _load_status_notification_state(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_status_notification_state(path, state):
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(state, handle, indent=2)


def _build_status_issues(db_status, google_status, google_token, config_checks, storage_checks):
    issues = []
    if not db_status.get('ok'):
        issues.append(f"Database: {db_status.get('detail', 'error')}")
    if not google_status.get('ok'):
        issues.append(f"Google Admin SDK: {google_status.get('detail', 'error')}")
    if not google_token.get('ok'):
        issues.append(f"Google token: {google_token.get('detail', 'error')}")
    for item in config_checks:
        if item.get('ok') is False:
            issues.append(f"Config {item.get('name')}: {item.get('detail')}")
    for item in storage_checks:
        if item.get('ok') is False:
            issues.append(f"Storage {item.get('name')}: {item.get('detail')}")
    return issues


def _email_config_ready():
    recipients = app.config.get('STATUS_EMAIL_RECIPIENTS', [])
    host = app.config.get('SMTP_HOST')
    sender = app.config.get('SMTP_FROM') or app.config.get('SMTP_USER')
    if not host or not sender or not recipients:
        return False
    if app.config.get('SMTP_USER') and not app.config.get('SMTP_PASSWORD'):
        return False
    return True


def _maybe_send_status_email(db_status, google_status, google_token, config_checks, storage_checks):
    if not app.config.get('STATUS_EMAIL_ENABLED'):
        return
    if not _email_config_ready():
        return

    recipients = app.config.get('STATUS_EMAIL_RECIPIENTS', [])
    issues = _build_status_issues(db_status, google_status, google_token, config_checks, storage_checks)
    state_path = os.path.join(app.root_path, 'data', STATUS_NOTIFICATION_FILE)
    state = _load_status_notification_state(state_path)
    last_status = state.get('last_status', 'ok')
    last_signature = state.get('last_issue_signature', '')
    last_sent_at = float(state.get('last_sent_at', 0) or 0)

    cooldown_minutes = app.config.get('STATUS_EMAIL_COOLDOWN_MINUTES', 30)
    cooldown_seconds = max(0, int(cooldown_minutes) * 60)
    now_ts = time.time()
    base_url = app.config.get('BASE_URL') or 'ResetApp'
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    if issues:
        signature = '|'.join(sorted(issues))
        should_send = signature != last_signature or (now_ts - last_sent_at) >= cooldown_seconds
        if not should_send:
            return
        subject = '[ResetApp] OUTAGE detected'
        body_lines = [
            f"ResetApp status check at {timestamp}",
            f"Base URL: {base_url}",
            "",
            "Detected issues:",
        ]
        body_lines.extend([f"- {issue}" for issue in issues])
        if app.config.get('BASE_URL'):
            body_lines.extend(["", f"Status page: {app.config.get('BASE_URL').rstrip('/')}/status"])
        body = "\n".join(body_lines)
        try:
            send_email(subject, body, recipients)
        except Exception:
            logger.exception('Status email send failed')
            return
        state['last_status'] = 'fail'
        state['last_issue_signature'] = signature
        state['last_sent_at'] = now_ts
        _save_status_notification_state(state_path, state)
        return

    if last_status == 'fail':
        if app.config.get('STATUS_EMAIL_NOTIFY_ON_RECOVERY', True):
            subject = '[ResetApp] RECOVERY'
            body_lines = [
                f"ResetApp status check at {timestamp}",
                f"Base URL: {base_url}",
                "",
                "All checks are passing.",
            ]
            if app.config.get('BASE_URL'):
                body_lines.extend(["", f"Status page: {app.config.get('BASE_URL').rstrip('/')}/status"])
            body = "\n".join(body_lines)
            try:
                send_email(subject, body, recipients)
            except Exception:
                logger.exception('Status email send failed')
                return
        state['last_status'] = 'ok'
        state['last_issue_signature'] = ''
        _save_status_notification_state(state_path, state)


def _collect_status_data():
    db_status = {'ok': False, 'detail': ''}
    db_details = []
    db_counts = []
    db_schema_time = 'n/a'
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text('SELECT 1'))
            tables = [
                ('audit_logs', audit_logs_table),
                ('admin_users', admin_users_table),
                ('bug_reports', bug_reports_table),
                ('classroom_sync', classroom_sync_table),
                ('global_admins', global_admins_table),
                ('known_issues', known_issues_table),
                ('login_logs', login_logs_table),
                ('reset_requests', reset_requests_table),
                ('theme_preferences', theme_preferences_table),
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

    build_info = _get_build_metadata()
    app_info = [
        {'name': 'Version', 'detail': build_info['version']},
        {'name': 'Commit', 'detail': build_info['commit']},
        {'name': 'Build time', 'detail': build_info['build_time']},
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

    email_enabled = app.config.get('STATUS_EMAIL_ENABLED', False)
    email_ready = _email_config_ready()
    recipients = app.config.get('STATUS_EMAIL_RECIPIENTS', [])
    if not email_enabled:
        email_detail = 'disabled'
        email_ok = True
    elif email_ready:
        email_detail = ', '.join(recipients) if recipients else 'configured'
        email_ok = True
    else:
        email_detail = 'missing SMTP config/recipients'
        email_ok = False
    config_checks.append({
        'name': 'Status email',
        'detail': email_detail,
        'ok': email_ok,
    })

    data_dir = os.path.join(app.root_path, 'data')
    upload_dir = app.config.get('UPLOAD_FOLDER')
    data_ok, data_detail = _check_writable_dir(data_dir)
    upload_ok, upload_detail = _check_writable_dir(upload_dir)
    storage_checks = [
        {
            'name': 'Data directory writable',
            'detail': data_detail,
            'ok': data_ok,
        },
        {
            'name': 'Upload directory writable',
            'detail': upload_detail,
            'ok': upload_ok,
        },
    ]

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
                    db_schema_time = 'not initialized'
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

    return {
        'db_status': db_status,
        'google_status': google_status,
        'google_token': google_token,
        'classroom_sync_count': len(sync_data),
        'classroom_last_sync': last_sync,
        'app_info': app_info,
        'config_checks': config_checks,
        'storage_checks': storage_checks,
        'db_details': db_details,
        'db_counts': db_counts,
        'google_details': google_details,
        'runtime_details': runtime_details,
    }


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
    data = _collect_status_data()
    _maybe_send_status_email(
        data['db_status'],
        data['google_status'],
        data['google_token'],
        data['config_checks'],
        data['storage_checks']
    )
    return render_template('status.html', user=session.get('user_info'), **data)


@app.route('/status/notify')
def status_notify():
    token = request.args.get('token') or request.headers.get('X-Status-Token', '')
    expected = app.config.get('STATUS_EMAIL_TOKEN', '')
    if not expected or not token or not secrets.compare_digest(token, expected):
        abort(404)
    data = _collect_status_data()
    _maybe_send_status_email(
        data['db_status'],
        data['google_status'],
        data['google_token'],
        data['config_checks'],
        data['storage_checks']
    )
    issues = _build_status_issues(
        data['db_status'],
        data['google_status'],
        data['google_token'],
        data['config_checks'],
        data['storage_checks']
    )
    return jsonify({'ok': not issues, 'issues': len(issues)})


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
