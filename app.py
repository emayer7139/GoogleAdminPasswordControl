import os
import sys
import logging
import secrets
import string
from datetime import datetime
from functools import wraps

from flask import (
    Flask, redirect, url_for, session, request,
    render_template, flash, jsonify
)
from werkzeug.middleware.proxy_fix import ProxyFix
from google.oauth2 import id_token, service_account
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from config import Config

# ─── Logging ─────────────────────────────────────────────────────────
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logger = logging.getLogger(__name__)

# ─── Flask app + ProxyFix (trust X-Forwarded-*) ──────────────────────
app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# ─── In‑memory logs ─────────────────────────────────────────────────
audit_logs = []
login_logs = []

# ─── Helpers ────────────────────────────────────────────────────────
def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'google_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# ─── AUTH ROUTES ────────────────────────────────────────────────────
@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    flow = Flow.from_client_config(
        {'web': {
            'client_id':     app.config['GOOGLE_CLIENT_ID'],
            'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
            'auth_uri':      'https://accounts.google.com/o/oauth2/auth',
            'token_uri':     'https://oauth2.googleapis.com/token',
            'redirect_uris': [app.config['REDIRECT_URI']],
        }},
        scopes=[
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ]
    )
    flow.redirect_uri = app.config['REDIRECT_URI']
    # trust the proxy’s X-Forwarded-Proto header for https
    flow.oauth2session.trust_env = True

    auth_url, state = flow.authorization_url(
        prompt='consent',
        include_granted_scopes='true',
        access_type='offline'
    )
    session['state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        state = session.get('state')
        if request.args.get('state') != state:
            raise ValueError('CSRF state mismatch')

        flow = Flow.from_client_config(
            {'web': {
                'client_id':     app.config['GOOGLE_CLIENT_ID'],
                'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
                'auth_uri':      'https://accounts.google.com/o/oauth2/auth',
                'token_uri':     'https://oauth2.googleapis.com/token',
                'redirect_uris': [app.config['REDIRECT_URI']],
            }},
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile',
            ],
            state=state
        )
        flow.redirect_uri = app.config['REDIRECT_URI']
        flow.oauth2session.trust_env = True

        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        idinfo = id_token.verify_oauth2_token(
            creds.id_token,
            GoogleRequest(),
            app.config['GOOGLE_CLIENT_ID']
        )

        # store user info
        email = idinfo['email']
        session['google_id'] = idinfo['sub']
        session['user_info'] = {'email': email, 'name': idinfo['name']}

        # record login success
        login_logs.append({
            'timestamp': ts,
            'user': email,
            'outcome': 'Success'
        })

        # ─── STAFF‑ONLY GATE (allow super‑admins too) ───────────────
        svc_creds = service_account.Credentials.from_service_account_file(
            app.config['SERVICE_ACCOUNT_FILE'],
            scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly']
        ).with_subject(app.config['ADMIN_USER'])
        admin_svc = build('admin', 'directory_v1', credentials=svc_creds)

        me = admin_svc.users().get(userKey=email).execute()
        ou_path  = me.get('orgUnitPath', '')
        is_super = me.get('isAdmin', False)

        allowed_ous = [
            '/Staff/District',
            '/Staff/Faculty',
            '/Staff/Long Term Subs',
            '/Staff/School Admins',
        ]
        if not (is_super or any(ou_path.startswith(prefix) for prefix in allowed_ous)):
            flash('Only authorized staff may sign in.', 'danger')
            session.clear()
            return redirect(url_for('login_page'))

        return redirect(url_for('index'))

    except Exception as e:
        # record failure
        login_logs.append({
            'timestamp': ts,
            'user': session.get('user_info', {}).get('email', 'unknown'),
            'outcome': f'Failure: {e}'
        })
        flash(f'Login failed: {e}', 'danger')
        return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ─── MAIN APP ────────────────────────────────────────────────────────
@app.route('/', methods=['GET','POST'])
@login_required
def index():
    user           = session['user_info']
    new_password   = None
    student_email  = None
    student_name   = None
    outcome        = ''

    if request.method == 'POST':
        student_email = request.form.get('student_email','').strip()
        student_name  = request.form.get('student_name','').strip()

        if not student_email:
            flash('Enter a student email.', 'danger')
            outcome = 'Canceled: no email'
        else:
            creds = service_account.Credentials.from_service_account_file(
                app.config['SERVICE_ACCOUNT_FILE'],
                scopes=['https://www.googleapis.com/auth/admin.directory.user']
            ).with_subject(app.config['ADMIN_USER'])
            svc = build('admin', 'directory_v1', credentials=creds)

            try:
                teacher = svc.users().get(userKey=user['email']).execute()
                student = svc.users().get(userKey=student_email).execute()

                # only reset /Students
                if not student.get('orgUnitPath','').startswith('/Students'):
                    flash("I can only reset student passwords.", 'danger')
                    outcome = 'Denied: not a student'

                # optional: same‑OU enforcement
                elif teacher.get('orgUnitPath') != student.get('orgUnitPath'):
                    flash("No permission to reset that student's password.", 'danger')
                    outcome = 'Denied: wrong OU'

                else:
                    new_password = generate_password(12)
                    svc.users().update(
                        userKey=student_email,
                        body={'password': new_password, 'changePasswordAtNextLogin': True}
                    ).execute()
                    flash('Password reset! It will disappear in 2 minutes.', 'success')
                    outcome = 'Success'

            except Exception as e:
                logger.error("Reset error", exc_info=True)
                flash(f'Error resetting password: {e}', 'danger')
                outcome = f'Error: {e}'

        audit_logs.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'admin':     user['email'],
            'student':   f"{student_email} ({student_name})" if student_name else student_email,
            'outcome':   outcome
        })

    return render_template(
        'index.html',
        user=user,
        new_password=new_password,
        student_email=student_email,
        student_name=student_name
    )

# ─── AJAX USER SUGGESTION ────────────────────────────────────────────
@app.route('/search_users')
@login_required
def search_users():
    q = request.args.get('q','').strip()
    if not q:
        return jsonify([])

    creds = service_account.Credentials.from_service_account_file(
        app.config['SERVICE_ACCOUNT_FILE'],
        scopes=[
            'https://www.googleapis.com/auth/admin.directory.user.readonly',
            'https://www.googleapis.com/auth/admin.directory.user'
        ]
    ).with_subject(app.config['ADMIN_USER'])
    svc = build('admin','directory_v1',credentials=creds)

    tokens = q.split()
    candidates = []
    try:
        for field in ('givenName','familyName','email'):
            resp = svc.users().list(
                customer='my_customer',
                query=f"{field}:{tokens[0]}*",
                maxResults=20
            ).execute()
            candidates.extend(resp.get('users',[]))
    except HttpError:
        return jsonify([]), 500

    # dedupe & multi‑token filter
    unique = {}
    for u in candidates:
        email = u.get('primaryEmail')
        if email and email not in unique:
            unique[email] = u
    candidates = list(unique.values())

    if len(tokens)>1:
        rest = [t.lower() for t in tokens[1:]]
        candidates = [
            u for u in candidates
            if all(any(val.startswith(tk) for val in (
                u['name'].get('givenName','').lower(),
                u['name'].get('familyName','').lower(),
                u.get('primaryEmail','').split('@')[0].lower()
            )) for tk in rest)
        ]

    return jsonify([
        {
            'label': f"{u['name'].get('givenName','')} {u['name'].get('familyName','')}, {u.get('primaryEmail','').split('@')[0]}",
            'value': u.get('primaryEmail','')
        }
        for u in candidates
    ])

# ─── MISC PAGES ─────────────────────────────────────────────────────
@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/instructions')
@login_required
def instructions_page():
    return render_template('instructions.html', user=session['user_info'])

@app.route('/documentation')
@login_required
def documentation_page():
    return render_template('documentation.html', user=session['user_info'])

@app.route('/updates')
@login_required
def updates_page():
    return render_template('updates.html', user=session['user_info'])

@app.route('/admin')
@login_required
def admin_page():
    user = session['user_info']
    sa_path = app.config['SERVICE_ACCOUNT_FILE']

    # 1) Sanity‑check your service‑account JSON file
    if not os.path.isfile(sa_path):
        flash(f"Service account file not found: {sa_path}", "danger")
        return render_template('admin.html',
                               user=user,
                               users=[],
                               audit_logs=audit_logs,
                               login_logs=login_logs)

    # 2) Load the credentials
    try:
        creds = service_account.Credentials.from_service_account_file(
            sa_path,
            scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly']
        ).with_subject(app.config['ADMIN_USER'])
    except Exception as e:
        logger.error("SA load error: %s", e, exc_info=True)
        flash("Error loading service account credentials.", "danger")
        return render_template('admin.html',
                               user=user,
                               users=[],
                               audit_logs=audit_logs,
                               login_logs=login_logs)

    # 3) Build the Directory API client
    service = build('admin', 'directory_v1', credentials=creds)

    # 4) Fetch all users via pagination
    users = []
    page_token = None
    while True:
        resp = service.users().list(
            customer='my_customer',
            maxResults=500,       # API max per page
            orderBy='email',
            pageToken=page_token
        ).execute()
        users.extend(resp.get('users', []))
        page_token = resp.get('nextPageToken')
        if not page_token:
            break

    # 5) Render the admin dashboard with every user
    return render_template(
        'admin.html',
        user=user,
        users=users,
        audit_logs=audit_logs,
        login_logs=login_logs
    )


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

