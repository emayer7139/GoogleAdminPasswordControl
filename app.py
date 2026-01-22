import logging
import os
import sys
import atexit

from flask import Flask, render_template, session
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from extensions import limiter
from services.storage import persist_audit_logs, load_known_issues, load_classroom_sync
from services.db import init_db, get_engine
from services.google_admin import get_user_summary
from sqlalchemy import text
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
    try:
        with get_engine().connect() as conn:
            conn.execute(text('SELECT 1'))
        db_status['ok'] = True
        db_status['detail'] = 'Connected'
    except Exception as exc:
        db_status['detail'] = str(exc)

    google_status = {'ok': False, 'detail': ''}
    try:
        admin_user = app.config.get('ADMIN_USER')
        if not app.config.get('SERVICE_ACCOUNT_FILE'):
            raise RuntimeError('SERVICE_ACCOUNT_FILE not set')
        if not admin_user:
            raise RuntimeError('ADMIN_USER not set')
        get_user_summary(admin_user)
        google_status['ok'] = True
        google_status['detail'] = 'Admin SDK OK'
    except Exception as exc:
        google_status['detail'] = str(exc)

    sync_data = load_classroom_sync()
    last_sync = ''
    if sync_data:
        last_sync = max(
            (v.get('timestamp', '') for v in sync_data.values()),
            default=''
        )

    return render_template(
        'status.html',
        user=session.get('user_info'),
        db_status=db_status,
        google_status=google_status,
        classroom_sync_count=len(sync_data),
        classroom_last_sync=last_sync
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
