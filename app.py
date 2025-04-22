import os
# Allow HTTP for OAuth in development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
import os
import logging


import sys, logging, secrets, string
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
from datetime import datetime
from config import Config
from datetime import datetime

# in‐memory logs
audit_logs = []
login_logs = []

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Logging
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

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

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    flow = Flow.from_client_config(
        {'web': {
            'client_id': app.config['GOOGLE_CLIENT_ID'],
            'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
            'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'redirect_uris': [app.config['REDIRECT_URI']],
        }},
        scopes=[
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
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
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        state = session.get('state')
        if request.args.get('state') != state:
            raise ValueError('CSRF state mismatch')
        flow = Flow.from_client_config(
            {'web': {
                'client_id': app.config['GOOGLE_CLIENT_ID'],
                'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [app.config['REDIRECT_URI']],
            }},
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ],
            state=state
        )
        flow.redirect_uri = app.config['REDIRECT_URI']
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        idinfo = id_token.verify_oauth2_token(
            creds.id_token,
            GoogleRequest(),
            app.config['GOOGLE_CLIENT_ID']
        )

        # Success!
        session['google_id'] = idinfo['sub']
        session['user_info'] = {'email': idinfo['email'], 'name': idinfo['name']}
        login_logs.append({
            'timestamp': ts,
            'user': idinfo['email'],
            'outcome': 'Success'
        })
        return redirect(url_for('index'))

    except Exception as e:
        # Failure
        user = request.args.get('email', 'unknown')
        login_logs.append({
            'timestamp': ts,
            'user': user,
            'outcome': f'Failure: {e}'
        })
        flash(f'Login failed: {e}', 'danger')
        return redirect(url_for('login_page'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user = session['user_info']
    new_password = None
    student_email = None
    student_name = None

    if request.method == 'POST':
        student_email = request.form.get('student_email')
        student_name  = request.form.get('student_name')
        outcome = ''
        if not student_email:
            flash('Enter a student email.', 'danger')
            outcome = 'Canceled: no email'
        else:
            try:
                creds = service_account.Credentials.from_service_account_file(
                    app.config['SERVICE_ACCOUNT_FILE'],
                    scopes=['https://www.googleapis.com/auth/admin.directory.user']
                )
                delegated = creds.with_subject(app.config['ADMIN_USER'])
                service = build('admin', 'directory_v1', credentials=delegated)

                teacher = service.users().get(userKey=user['email']).execute()
                student = service.users().get(userKey=student_email).execute()
                if teacher.get('orgUnitPath') != student.get('orgUnitPath'):
                    flash("No permission to reset that student's password.", 'danger')
                    outcome = 'Denied: wrong OU'
                else:
                    new_password = generate_password(12)
                    service.users().update(
                        userKey=student_email,
                        body={'password': new_password, 'changePasswordAtNextLogin': True}
                    ).execute()
                    flash('Password reset! It will disappear in 2 minutes.', 'success')
                    outcome = 'Success'

            except Exception as e:
                logger.error("Reset error: %s", e, exc_info=True)
                flash(f'Error resetting password: {e}', 'danger')
                outcome = f'Error: {e}'

        audit_logs.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'admin': user['email'],
            'student': f"{student_email} ({student_name})" if student_name else student_email,
            'outcome': outcome
        })

    return render_template(
        'index.html',
        user=user,
        new_password=new_password,
        student_email=student_email,
        student_name=student_name
    )


@app.route('/search_users')
@login_required
def search_users():
    # ... your existing search_users code unchanged ...
    # returns JSON [{label,value},...]
    ...


@app.route('/help')
def help_page():
    return render_template('help.html')


@app.route('/instructions')
@login_required
def instructions_page():
    return render_template('instructions.html', user=session.get('user_info'))


@app.route('/admin')
@login_required
def admin_page():
    user = session['user_info']
    sa_path = app.config['SERVICE_ACCOUNT_FILE']

    # 1) sanity‑check SA JSON
    if not os.path.isfile(sa_path):
        flash(f"Service account file not found: {sa_path}", "danger")
        return render_template('admin.html',
                               user=user,
                               users=[],
                               audit_logs=audit_logs,
                               login_logs=login_logs)

    # 2) load credentials
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

    # 3) build Directory client
    service = build('admin', 'directory_v1', credentials=creds)

    # 4) fetch ALL users via list_next()
    users = []
    request = service.users().list(
        customer='my_customer',
        maxResults=500,
        orderBy='email'
    )
    while request:
        response = request.execute()
        batch = response.get('users', [])
        logger.debug("Fetched %d users in this page", len(batch))
        users.extend(batch)
        request = service.users().list_next(request, response)

    logger.info("Total users fetched: %d", len(users))

    # 5) render
    return render_template(
        'admin.html',
        user=user,
        users=users,
        audit_logs=audit_logs,
        login_logs=login_logs
    )


@login_required
def admin_page():
    creds = service_account.Credentials.from_service_account_file(
        app.config['SERVICE_ACCOUNT_FILE'],
        scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly']
    ).with_subject(app.config['ADMIN_USER'])
    service = build('admin', 'directory_v1', credentials=creds)

    resp = service.users().list(
        customer='my_customer', maxResults=200, orderBy='email'
    ).execute()
    users = resp.get('users', [])

    return render_template(
        'admin.html',
        user=session['user_info'],
        users=users,
        audit_logs=audit_logs,
        login_logs=login_logs
    )

@app.route('/updates')
@login_required
def updates_page():
    return render_template('updates.html', user=session.get('user_info'))

@app.route('/documentation')
@login_required
def documentation():
    return render_template('documentation.html', user=session.get('user_info'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
