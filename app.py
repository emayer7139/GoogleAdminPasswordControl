import os
import sys
import logging
import secrets
import string

from functools import wraps
from flask import (
    Flask, redirect, url_for, session, request,
    render_template, flash, jsonify
)
from google.oauth2 import id_token, service_account
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config

# ─── Logging ─────────────────────────────────────────────────────────
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logger = logging.getLogger(__name__)

# ─── Create Flask app + ProxyFix ─────────────────────────────────────
app = Flask(__name__, static_folder='static', template_folder='templates')
# trust X-Forwarded headers from nginx
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# ─── Helpers ─────────────────────────────────────────────────────────
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
    auth_url, state = flow.authorization_url(
        prompt='consent',
        include_granted_scopes='true',
        access_type='offline'
    )
    session['state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    # finish OAuth handshake
    state = session.get('state')
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

    # CSRF/state check
    if request.args.get('state') != state:
        logger.error("State mismatch: %s vs %s", request.args.get('state'), state)
        return "CSRF state mismatch", 400

    # Exchange code → tokens
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    # Verify ID token
    try:
        idinfo = id_token.verify_oauth2_token(
            creds.id_token,
            GoogleRequest(),
            app.config['GOOGLE_CLIENT_ID']
        )
    except Exception as e:
        logger.error("Token verify failed", exc_info=True)
        return "Token verification failed", 400

    email = idinfo['email']
    session['google_id'] = idinfo['sub']
    session['user_info'] = {'email': email, 'name': idinfo['name']}

    # ─── STAFF‑ONLY GATE (plus super‑admins) ──────────────────────────
    svc_creds = service_account.Credentials.from_service_account_file(
        app.config['SERVICE_ACCOUNT_FILE'],
        scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly']
    ).with_subject(app.config['ADMIN_USER'])
    admin_svc = build('admin', 'directory_v1', credentials=svc_creds)

    try:
        me       = admin_svc.users().get(userKey=email).execute()
        ou_path  = me.get('orgUnitPath', '')
        is_super = me.get('isAdmin', False)
    except HttpError as e:
        logger.error("Unable to fetch own account info: %s", e, exc_info=True)
        flash("Authentication error", 'danger')
        session.clear()
        return redirect(url_for('login_page'))

    # allow staff OUs or any Google super-admin
    allowed_ous = [
        '/Staff/District',
        '/Staff/Faculty',
        '/Staff/Long Term Subs',
        '/Staff/School Admins',
    ]
    if not (is_super or any(ou_path.startswith(p) for p in allowed_ous)):
        flash('Only authorized staff may sign in.', 'danger')
        session.clear()
        return redirect(url_for('login_page'))

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ─── MAIN APP ────────────────────────────────────────────────────────
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user           = session['user_info']
    new_password   = None
    student_email  = None
    student_name   = None

    if request.method == 'POST':
        student_email = request.form.get('student_email','').strip()
        student_name  = request.form.get('student_name','').strip()

        if not student_email:
            flash('Enter a student email.', 'danger')
        else:
            creds = service_account.Credentials.from_service_account_file(
                app.config['SERVICE_ACCOUNT_FILE'],
                scopes=['https://www.googleapis.com/auth/admin.directory.user']
            ).with_subject(app.config['ADMIN_USER'])
            svc = build('admin', 'directory_v1', credentials=creds)

            try:
                teacher     = svc.users().get(userKey=user['email']).execute()
                teacher_ou  = teacher.get('orgUnitPath','')
                student     = svc.users().get(userKey=student_email).execute()
                student_ou  = student.get('orgUnitPath','')

                # only reset real students
                if not student_ou.startswith('/Students'):
                    flash("I can only reset student passwords.", 'danger')
                # optional: enforce same OU
                elif teacher_ou != student_ou:
                    flash("No permission to reset that student's password.", 'danger')
                else:
                    new_password = generate_password(12)
                    svc.users().update(
                        userKey=student_email,
                        body={
                            'password': new_password,
                            'changePasswordAtNextLogin': True
                        }
                    ).execute()
                    flash('Password reset! It will disappear in 2 minutes.', 'success')

            except Exception as e:
                logger.error("Reset error", exc_info=True)
                flash(f'Error resetting password: {e}', 'danger')

    return render_template(
        'index.html',
        user=user,
        new_password=new_password,
        student_email=student_email,
        student_name=student_name,
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
            query = f"{field}:{tokens[0]}*"
            resp = svc.users().list(
                customer='my_customer',
                query=query,
                maxResults=20
            ).execute()
            candidates.extend(resp.get('users',[]))
    except HttpError as e:
        logger.error("Directory search error", exc_info=True)
        return jsonify([]), 500

    # dedupe
    unique = {}
    for u in candidates:
        email = u.get('primaryEmail')
        if email and email not in unique:
            unique[email] = u
    candidates = list(unique.values())

    # multi‑token filter
    if len(tokens)>1:
        rest = [t.lower() for t in tokens[1:]]
        filtered=[]
        for u in candidates:
            fn, ln = u['name'].get('givenName','').lower(), u['name'].get('familyName','').lower()
            num     = u.get('primaryEmail','').split('@')[0].lower()
            if all(any(val.startswith(tk) for val in (fn,ln,num)) for tk in rest):
                filtered.append(u)
        candidates = filtered

    # build suggestions
    out = []
    for u in candidates:
        first  = u['name'].get('givenName','')
        last   = u['name'].get('familyName','')
        email  = u.get('primaryEmail','')
        number = email.split('@')[0]
        label  = f"{first} {last}, {number}"
        out.append({'label':label,'value':email})
    return jsonify(out)

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/admin')
@login_required
def admin_page():
    return render_template('admin.html', user=session.get('user_info'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

