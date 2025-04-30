import os
import sys
import json
import logging
import secrets
import string
from datetime import datetime, date
from functools import wraps

from flask import (
    Flask, redirect, url_for, session, request,
    render_template, flash, jsonify, abort
)
from werkzeug.middleware.proxy_fix import ProxyFix

from google.oauth2 import id_token, service_account
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cachetools import TTLCache
import time

# ─── Logging ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# ─── Flask app + ProxyFix (trust X-Forwarded-*) ──────────────────────
app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# Add Flask-Limiter for rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ─── In-memory logs and caches ──────────────────────────────────────
audit_logs = []
login_logs = []
admin_api_cache = TTLCache(maxsize=100, ttl=300)  # 5 min cache for Admin API responses

# ─── Persistence stores ───────────────────────────────────────────────
ADMIN_FILE    = os.path.join(app.root_path, 'admin_users.json')
REQUESTS_FILE = os.path.join(app.root_path, 'reset_requests.json')
RESET_LIMIT   = app.config.get('RESET_LIMIT', 5)

def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path,'r') as f:
        return json.load(f)

def save_json(path,data):
    with open(path,'w') as f:
        json.dump(data,f,indent=2)

def load_admins():
    return load_json(ADMIN_FILE)

def save_admins(admins):
    save_json(ADMIN_FILE,admins)

def load_requests():
    return load_json(REQUESTS_FILE)

def save_requests(reqs):
    save_json(REQUESTS_FILE,reqs)

# ─── Helpers ────────────────────────────────────────────────────────
def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def log_failed_login(email, reason):
    login_logs.append({'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'user': email, 'outcome': f'Failed: {reason}'})
    logger.warning(f"[LOGIN] Failed login for {email}: {reason}")
    save_json(os.path.join(app.root_path, 'login_logs.json'), login_logs)

def persist_audit_logs():
    save_json(os.path.join(app.root_path, 'audit_logs.json'), audit_logs)

# ─── Auth decorators ─────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        if 'google_id' not in session:
            log_failed_login(session.get('user_info',{}).get('email','Unknown'), 'Not logged in')
            return redirect(url_for('login_page'))
        # Absolute session timeout (1 hour)
        if 'last_active' in session and (datetime.now() - session['last_active']).total_seconds() > 3600:
            session.clear()
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login_page'))
        session['last_active'] = datetime.now()
        return f(*args,**kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        email = session.get('user_info',{}).get('email','').lower()
        if email not in load_admins():
            abort(403)
        # Regenerate session on privilege change
        session.modified = True
        return f(*args,**kwargs)
    return decorated

# ─── AUTH ROUTES ────────────────────────────────────────────────────
@app.route('/login')
def login_page():
    if 'google_id' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/login/google')
@limiter.limit("10 per minute")
def login_google():
    flow = Flow.from_client_config(
        {'web': {
            'client_id':     app.config['GOOGLE_CLIENT_ID'],
            'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
            'auth_uri':      'https://accounts.google.com/o/oauth2/auth',
            'token_uri':     'https://oauth2.googleapis.com/token',
            'redirect_uris':[app.config['REDIRECT_URI']],
        }},
        scopes=[
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ]
    )
    flow.redirect_uri = app.config['REDIRECT_URI']
    flow.oauth2session.trust_env = True

    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='select_account'
    )
    session['state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
@limiter.limit("10 per minute")
def oauth2callback():
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info("[OAUTH2] Starting callback")
    try:
        # Get state before clearing session
        state = session.get('state')
        logger.info("[OAUTH2] State from session: %s", state)
        
        # Clear session but preserve state
        session.clear()
        if state:
            session['state'] = state
        if not state or request.args.get('state') != state:
            logger.error("[OAUTH2] State mismatch or missing")
            raise ValueError('Invalid state parameter')

        flow = Flow.from_client_config(
            {'web': {
                'client_id':     app.config['GOOGLE_CLIENT_ID'],
                'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
                'auth_uri':      'https://accounts.google.com/o/oauth2/auth',
                'token_uri':     'https://oauth2.googleapis.com/token',
                'redirect_uris':[app.config['REDIRECT_URI']],
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
        logger.info("[OAUTH2] Flow created")

        # Get OAuth2 token
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        logger.info("[OAUTH2] Token fetched")

        # Verify the ID token
        idinfo = id_token.verify_oauth2_token(
            creds.id_token, GoogleRequest(), app.config['GOOGLE_CLIENT_ID']
        )
        logger.info("[OAUTH2] ID token verified")

        # Extract user info
        email = idinfo['email']
        name = idinfo.get('name', '')
        logger.info("[OAUTH2] User info extracted: %s, %s", email, name)

        # Set session data
        session['google_id'] = idinfo['sub']
        session['user_info'] = {'email': email, 'name': name}
        session['csrf_token'] = secrets.token_hex(16)
        logger.info("[OAUTH2] Session data set")

        # Log the successful login
        login_logs.append({'timestamp':ts,'user':email,'outcome':'Success'})
        logger.info("[OAUTH2] Login logged")

        # Check staff status
        logger.info("[STAFF] Starting check for %s", email)
        try:
            # Admin API cache key
            cache_key = f"{email}_staff_check"
            user_data = admin_api_cache.get(cache_key)
            if not user_data:
                # Create service account credentials
                credentials = service_account.Credentials.from_service_account_file(
                    app.config['SERVICE_ACCOUNT_FILE'],
                    scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly']
                ).with_subject(app.config['ADMIN_USER'])
                from google.auth.transport.requests import AuthorizedSession
                authed_session = AuthorizedSession(credentials)
                # Exponential backoff for API call
                for attempt in range(4):
                    response = authed_session.get(
                        f'https://admin.googleapis.com/admin/directory/v1/users/{email}',
                        params={'fields': 'orgUnitPath,isAdmin', 'prettyPrint': 'false'}
                    )
                    if response.status_code == 200:
                        user_data = response.json()
                        admin_api_cache[cache_key] = user_data
                        break
                    elif response.status_code in (403, 404):
                        logger.error("[STAFF] API error: %s", response.text)
                        raise Exception(f"Admin API error: {response.status_code}")
                    else:
                        logger.warning("[STAFF] API error %s, retrying...", response.status_code)
                        time.sleep(2 ** attempt)
                else:
                    raise Exception("Admin API failed after retries")
            logger.info("[STAFF] User data received: %s", user_data)

            ou_path = user_data.get('orgUnitPath', '')
            is_super = user_data.get('isAdmin', False)
            logger.info("[STAFF] User %s OU path: %s, isAdmin: %s", email, ou_path, is_super)

            is_staff = (
                is_super or 
                ou_path.startswith('/Staff/') or 
                ou_path == '/Staff'
            )
            logger.info("[STAFF] Staff check result: %s", is_staff)

            if not is_staff:
                logger.warning("[STAFF] Access denied for %s", email)
                session.clear()
                flash('Only authorized staff may sign in.', 'danger')
                return redirect(url_for('login_page'))

            logger.info("[STAFF] Access granted for %s", email)
            return redirect(url_for('index'))

        except Exception as e:
            log_failed_login(email, f"Staff check failed: {str(e)}")
            session.clear()
            flash('Error verifying staff status. Please contact your administrator.', 'danger')
            return redirect(url_for('login_page'))

    except Exception as e:
        log_failed_login('Unknown', f"OAuth2 error: {str(e)}")
        session.clear()
        flash('Login failed. Please try again.', 'danger')
        return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ─── MAIN APP with RESET LIMIT ───────────────────────────────────────
@app.route('/', methods=['GET','POST'])
@login_required  # This will redirect to login if not authenticated
def index():
    try:
        user_info = session.get('user_info')
        if not user_info:
            logger.warning("No user_info in session, redirecting to login")
            return redirect(url_for('login_page'))

        today = date.today().isoformat()
        done = sum(
            1 for a in audit_logs
            if a.get('admin')==user_info['email']
            and a['timestamp'].startswith(today)
            and a.get('outcome')=='Success'
        )

        new_pw = None
        se = sn = outcome = ''

        if request.method=='POST':
            #CSRF Check
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                abort(403) #if invalid, forbidden
            if done >= RESET_LIMIT:
                flash("Daily limit reached.", "danger")
                token_val = session.get('csrf_token') #token link to request more resets
                flash("Request more <a href='/request_more'>here</a>.", "info")
            else:
                se = request.form.get('student_email','').strip()
                sn = request.form.get('student_name','').strip()
                if not se:
                    flash('Enter a student email.', 'danger')
                    outcome='Canceled'
                else:
                    creds = service_account.Credentials.from_service_account_file(
                        app.config['SERVICE_ACCOUNT_FILE'],
                        scopes=['https://www.googleapis.com/auth/admin.directory.user']
                    ).with_subject(app.config['ADMIN_USER'])
                    svc = build('admin','directory_v1',credentials=creds)
                    try:
                        teacher = svc.users().get(userKey=user_info['email']).execute()
                        student = svc.users().get(userKey=se).execute()
                        if not student.get('orgUnitPath','').startswith('/Students'):
                            flash("Only student OU.",'danger'); outcome='Denied'
                        elif teacher.get('orgUnitPath')!=student.get('orgUnitPath'):
                            flash("No permission.",'danger'); outcome='Denied'
                        else:
                            new_pw = generate_password(12)
                            svc.users().update(userKey=se,
                                body={'password':new_pw,'changePasswordAtNextLogin':True}
                            ).execute()
                            flash('Password reset!', 'success'); outcome='Success'
                    except Exception as e:
                        logger.error("Reset error",exc_info=True)
                        flash(f'Error: {e}','danger'); outcome='Error'
                audit_logs.append({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'admin':     user_info['email'],
                    'student':   f"{se} ({sn})" if sn else se,
                    'outcome':   outcome
                })

        return render_template('index.html',
            user=user_info,
            new_password=new_pw,
            student_email=se,
            student_name=sn
        )
    except Exception as e:
        logger.error("Error in index route: %s", str(e), exc_info=True)
        flash("An error occurred. Please try logging in again.", "danger")
        session.clear()
        return redirect(url_for('login_page'))

# ─── Request more resets ─────────────────────────────────────────────
@app.route('/request_more')
@login_required
def request_more():
    token = request.args.get('token')
    if not token or token != session.get('csrf_token'):
       abort(403)
    reqs = load_requests()
    rid = secrets.token_hex(4)
    reqs.append({
      'id':rid,
      'email':session['user_info']['email'],
      'date':date.today().isoformat(),
      'status':'Pending'
    })
    save_requests(reqs)
    flash("Request submitted.", "success")
    return redirect(url_for('index'))

# ─── AJAX USER SUGGESTION (STUDENTS only) ───────────────────────────
@app.route('/search_users')
@login_required
def search_users():
    q = request.args.get('q','').strip()
    if not q: return jsonify([])

    creds = service_account.Credentials.from_service_account_file(
        app.config['SERVICE_ACCOUNT_FILE'],
        scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly']
    ).with_subject(app.config['ADMIN_USER'])
    svc = build('admin','directory_v1',credentials=creds)

    toks = q.split()
    cand = []
    try:
        for f in ('givenName','familyName','email'):
            resp = svc.users().list(
              customer='my_customer',
              query=f"{f}:{toks[0]}*",
              maxResults=50
            ).execute()
            cand.extend(resp.get('users',[]))
    except HttpError:
        return jsonify([]),500

    uniq  = {u['primaryEmail']:u for u in cand if u.get('primaryEmail')}
    studs = [u for u in uniq.values() if u.get('orgUnitPath','').startswith('/Students')]

    if len(toks)>1:
        rest = [t.lower() for t in toks[1:]]
        def match(u):
            parts = " ".join([
              u['name'].get('givenName','').lower(),
              u['name'].get('familyName','').lower(),
              u['primaryEmail'].split('@')[0].lower()
            ])
            return all(tok in parts for tok in rest)
        studs = [u for u in studs if match(u)]

    return jsonify([
      {'label':f"{u['name'].get('givenName','')} {u['name'].get('familyName','')}",
       'value':u['primaryEmail']}
      for u in studs
    ])

# ─── AJAX STAFF USER SUGGESTION ────────────────────────────────────
@app.route('/search_staff')
@login_required
@admin_required
def search_staff():
    q = request.args.get('q','').strip()
    if not q: return jsonify([])

    creds = service_account.Credentials.from_service_account_file(
        app.config['SERVICE_ACCOUNT_FILE'],
        scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly']
    ).with_subject(app.config['ADMIN_USER'])
    svc = build('admin','directory_v1',credentials=creds)

    toks = q.split()
    found = []
    try:
        for f in ('givenName','familyName','email'):
            resp = svc.users().list(
              customer='my_customer',
              query=f"{f}:{toks[0]}*",
              maxResults=50
            ).execute()
            found.extend(resp.get('users',[]))
    except HttpError:
        return jsonify([]),500

    unique = {u['primaryEmail']:u for u in found if u.get('primaryEmail')}
    staff_prefixes = [
        '/Staff/District','/Staff/Faculty',
        '/Staff/Long Term Subs','/Staff/School Admins'
    ]
    staff = [u for u in unique.values()
             if any(u.get('orgUnitPath','').startswith(p) for p in staff_prefixes)]

    if len(toks)>1:
        rest = [t.lower() for t in toks[1:]]
        def match(u):
            parts = " ".join([
              u['name'].get('givenName','').lower(),
              u['name'].get('familyName','').lower(),
              u['primaryEmail'].split('@')[0].lower()
            ])
            return all(tok in parts for tok in rest)
        staff = [u for u in staff if match(u)]

    return jsonify([
      {
        'label':f"{u['name'].get('givenName','')} {u['name'].get('familyName','')} — {u['primaryEmail']}",
        'value':u['primaryEmail']
      } for u in staff
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

# ─── Admin Dashboard ────────────────────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin_page():
    user = session['user_info']
    start = request.args.get('start_date')
    end   = request.args.get('end_date')

    def in_range(ts):
        dt = datetime.fromisoformat(ts)
        if start and dt < datetime.fromisoformat(start): return False
        if end   and dt > datetime.fromisoformat(end):   return False
        return True

    return render_template('admin.html',
        user=user,
        audit_logs=[a for a in audit_logs if in_range(a['timestamp'])],
        login_logs=[l for l in login_logs if in_range(l['timestamp'])],
        admin_users=load_admins(),
        requests_list=load_requests()
    )

# ─── Add / Remove Admin ──────────────────────────────────────────────
@app.route('/add_admin', methods=['POST'])
@login_required
@admin_required
def add_admin():
    #CSRF Check
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    email = request.form['email'].strip().lower()
    admins= load_admins()
    if email in admins:
        flash(f"{email} already an admin.","warning")
    else:
        admins.append(email); save_admins(admins)
        flash(f"Added {email}","success")
    return redirect(url_for('admin_page'))

@app.route('/remove_admin', methods=['POST'])
@login_required
@admin_required
def remove_admin():
    #CSRF Check
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    email = request.form['email'].strip().lower()
    admins= load_admins()
    if email not in admins:
        flash(f"{email} not found.","warning")
    elif email == session['user_info']['email'].lower():
        flash("Cannot remove yourself.","danger")
    else:
        admins.remove(email); save_admins(admins)
        flash(f"Removed {email}","success")
    return redirect(url_for('admin_page'))

# ─── Approve / Deny Reset Requests ──────────────────────────────────
@app.route('/approve_request', methods=['POST'])
@login_required
@admin_required
def approve_request():
    #CSRF Check
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    rid  = request.form['id']
    reqs = load_requests()
    for r in reqs:
        if r['id']==rid:
            r['status']='Approved'
            flash(f"Approved {rid}","success")
            break
    save_requests(reqs)
    return redirect(url_for('admin_page'))

@app.route('/deny_request', methods=['POST'])
@login_required
@admin_required
def deny_request():
    #CSRF Check
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    rid  = request.form['id']
    reqs = load_requests()
    for r in reqs:
        if r['id']==rid:
            r['status']='Denied'
            flash(f"Denied {rid}","info")
            break
    save_requests(reqs)
    return redirect(url_for('admin_page'))

# ─── Error handlers ─────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Persist audit logs on shutdown
import atexit
atexit.register(persist_audit_logs)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context='adhoc')
