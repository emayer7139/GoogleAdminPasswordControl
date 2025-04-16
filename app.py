import os
# Allow HTTP for OAuth in development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

import sys, logging, secrets, string
from functools import wraps

from flask import (
    Flask, redirect, url_for,
    session, request, render_template, flash
)
from google.oauth2 import id_token, service_account
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build

from config import Config

# Logging
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'google_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'google_id' not in session:
        return redirect(url_for('login'))

    user = session['user_info']
    new_password = None
    student_email = None

    if request.method == 'POST':
        student_email = request.form.get('student_email')
        if not student_email:
            flash('Enter a student email.', 'danger')
        else:
            try:
                creds = service_account.Credentials.from_service_account_file(
                    app.config['SERVICE_ACCOUNT_FILE'],
                    scopes=['https://www.googleapis.com/auth/admin.directory.user']
                )
                delegated = creds.with_subject(app.config['ADMIN_USER'])
                service = build('admin', 'directory_v1', credentials=delegated)

                teacher = service.users().get(
                    userKey=user['email']
                ).execute()
                student = service.users().get(
                    userKey=student_email
                ).execute()

                if teacher.get('orgUnitPath') != student.get('orgUnitPath'):
                    flash("No permission to reset that student's password.", 'danger')
                else:
                    new_password = generate_password(12)
                    service.users().update(
                        userKey=student_email,
                        body={'password': new_password, 'changePasswordAtNextLogin': True}
                    ).execute()
                    flash('Password reset! It will disappear in 2 minutes.', 'success')
            except Exception as e:
                logger.error("Reset error: %s", e, exc_info=True)
                flash(f'Error resetting password: {e}', 'danger')

    return render_template(
        'index.html',
        user=user,
        new_password=new_password,
        student_email=student_email
    )

@app.route('/login')
def login():
    flow = Flow.from_client_config(
        {
            'web': {
                'client_id': app.config['GOOGLE_CLIENT_ID'],
                'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [app.config['REDIRECT_URI']],
            }
        },
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
    state = session.get('state')
    flow = Flow.from_client_config(
        {
            'web': {
                'client_id': app.config['GOOGLE_CLIENT_ID'],
                'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [app.config['REDIRECT_URI']],
            }
        },
        scopes=[
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ],
        state=state
    )
    flow.redirect_uri = app.config['REDIRECT_URI']

    auth_resp = request.url
    if request.args.get('state') != state:
        logger.error("State mismatch: %s vs %s", request.args.get('state'), state)
        return "CSRF state mismatch", 400

    if 'code' not in request.args:
        return "Missing code", 400

    flow.fetch_token(authorization_response=auth_resp)
    creds = flow.credentials

    try:
        idinfo = id_token.verify_oauth2_token(
            creds.id_token,
            GoogleRequest(),
            app.config['GOOGLE_CLIENT_ID']
        )
    except Exception as e:
        logger.error("Token verify failed: %s", e, exc_info=True)
        return "Token verification failed", 400

    session['google_id'] = idinfo['sub']
    session['user_info'] = {'email': idinfo['email'], 'name': idinfo['name']}
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
