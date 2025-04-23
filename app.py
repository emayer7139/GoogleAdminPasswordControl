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

from config import Config

# DEV LOGIN BYPASS: set DEV_LOGIN_BYPASS="false" to disable
DEV_LOGIN_BYPASS = os.environ.get("DEV_LOGIN_BYPASS", "true").lower() in ("1","true")

from google.oauth2 import id_token, service_account
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# ─── Logging ─────────────────────────────────────────────────────────
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logger = logging.getLogger(__name__)

# ─── Flask app ───────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ─── Enforce HTTPS only in production ────────────────────────────────
@app.before_request
def enforce_https():
    if not Config.DEV_MODE and not request.is_secure:
        return redirect(request.url.replace("http://", "https://"), code=301)

# ─── In-memory logs ───────────────────────────────────────────────────
audit_logs = []
login_logs = []

# ─── Persistence stores ───────────────────────────────────────────────
ADMIN_FILE    = os.path.join(app.root_path, 'admin_users.json')
REQUESTS_FILE = os.path.join(app.root_path, 'reset_requests.json')
RESET_LIMIT   = app.config.get('RESET_LIMIT', 5)

def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def load_admins():
    return load_json(ADMIN_FILE)

def save_admins(admins):
    save_json(ADMIN_FILE, admins)

def load_requests():
    return load_json(REQUESTS_FILE)

def save_requests(reqs):
    save_json(REQUESTS_FILE, reqs)

# ─── Helpers ────────────────────────────────────────────────────────
def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ─── Auth decorators ─────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if DEV_LOGIN_BYPASS and 'user_info' not in session:
            session['user_info'] = {'email':'dev@local','name':'Dev User'}
            logger.debug("DEV_LOGIN_BYPASS: injected dev user_info")
        if 'user_info' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        email = session.get('user_info', {}).get('email', '').lower()
        admins = load_admins()

        # DEV bypass: let your local dev user in unconditionally
        if DEV_LOGIN_BYPASS and email == 'dev@local':
            return f(*args, **kwargs)

        if email not in admins:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ─── AUTH ROUTES ────────────────────────────────────────────────────
@app.route('/login')
def login_page():
    if DEV_LOGIN_BYPASS:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    if DEV_LOGIN_BYPASS:
        return redirect(url_for('index'))
    flow = Flow.from_client_config(
        {'web': {
            'client_id':     app.config['GOOGLE_CLIENT_ID'],
            'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
            'auth_uri':      'https://accounts.google.com/o/oauth2/auth',
            'token_uri':     'https://oauth2.googleapis.com/token',
        }},
        scopes=app.config.get('OAUTH2_SCOPES', [
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ])
    )
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    flow.oauth2session.trust_env = True
    auth_url, state = flow.authorization_url(
        prompt='consent', include_granted_scopes='true', access_type='offline'
    )
    session['state'] = state
    logger.debug("Redirecting to Google OAuth, state=%s", state)
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    if DEV_LOGIN_BYPASS:
        return redirect(url_for('index'))
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if session.get('state') != request.args.get('state'):
        flash('State mismatch. Try again.', 'danger')
        return redirect(url_for('login_page'))
    flow = Flow.from_client_config(
        {'web': {
            'client_id':     app.config['GOOGLE_CLIENT_ID'],
            'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
            'auth_uri':      'https://accounts.google.com/o/oauth2/auth',
            'token_uri':     'https://oauth2.googleapis.com/token',
        }},
        scopes=app.config['OAUTH2_SCOPES'],
        state=session['state']
    )
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    flow.oauth2session.trust_env = True
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    idinfo = id_token.verify_oauth2_token(
        creds.id_token, GoogleRequest(), app.config['GOOGLE_CLIENT_ID']
    )
    email = idinfo['email']
    session['user_info'] = {'email':email,'name':idinfo.get('name')}
    login_logs.append({'timestamp':ts,'user':email,'outcome':'Success'})
    # Staff-only gate
    try:
        svc_creds = service_account.Credentials.from_service_account_file(
            app.config['SERVICE_ACCOUNT_FILE'],
            scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly']
        ).with_subject(app.config['ADMIN_USER'])
        admin_svc = build('admin','directory_v1',credentials=svc_creds)
        me = admin_svc.users().get(userKey=email).execute()
        ou = me.get('orgUnitPath',''); super=me.get('isAdmin',False)
        allowed = ['/Staff/District','/Staff/Faculty','/Staff/Long Term Subs','/Staff/School Admins']
        if not (super or any(ou.startswith(p) for p in allowed)):
            flash('Only authorized staff.', 'danger')
            session.clear()
            return redirect(url_for('login_page'))
    except Exception as e:
        logger.error("Staff gate error: %s", e, exc_info=True)
        session.clear()
        flash('Authorization error.', 'danger')
        return redirect(url_for('login_page'))
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ─── MAIN APP with RESET LIMIT ───────────────────────────────────────
@app.route('/', methods=['GET','POST'])
@login_required
def index():
    user_info = session['user_info']
    today = date.today().isoformat()
    done = sum(1 for a in audit_logs
               if a.get('admin')==user_info['email'] and a['timestamp'].startswith(today)
               and a.get('outcome')=='Success')
    new_pw = None; se=None; sn=None; outcome=''
    if request.method=='POST':
        if done>=RESET_LIMIT:
            flash("Daily limit reached.", "danger")
            flash("Request more <a href='/request_more'>here</a>.", "info")
        else:
            se = request.form.get('student_email','').strip()
            sn = request.form.get('student_name','').strip()
            if not se:
                flash('Enter a student email.', 'danger'); outcome='Canceled'
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
                        svc.users().update(userKey=se,body={
                            'password':new_pw,'changePasswordAtNextLogin':True
                        }).execute()
                        flash('Password reset!', 'success'); outcome='Success'
                except Exception as e:
                    logger.error("Reset error",exc_info=True)
                    flash(f'Error: {e}','danger'); outcome=f'Error'
            audit_logs.append({
                'timestamp':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'admin':user_info['email'],
                'student':f"{se} ({sn})" if sn else se,
                'outcome':outcome
            })
    return render_template('index.html',
        user=user_info, new_password=new_pw,
        student_email=se, student_name=sn
    )

# ─── Request more resets ─────────────────────────────────────────────
@app.route('/request_more')
@login_required
def request_more():
    reqs = load_requests()
    rid = secrets.token_hex(4)
    reqs.append({'id':rid,'email':session['user_info']['email'],
                 'date':date.today().isoformat(),'status':'Pending'})
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
    toks, cand = q.split(), []
    try:
        for f in ('givenName','familyName','email'):
            resp = svc.users().list(customer='my_customer',
                query=f"{f}:{toks[0]}*", maxResults=50).execute()
            cand.extend(resp.get('users',[]))
    except HttpError:
        return jsonify([]),500
    uniq = {u['primaryEmail']:u for u in cand if u.get('primaryEmail')}
    studs = [u for u in uniq.values() if u.get('orgUnitPath','').startswith('/Students')]
    if len(toks)>1:
        rest=[t.lower() for t in toks[1:]]
        def match(u):
            parts=" ".join([
                u['name'].get('givenName','').lower(),
                u['name'].get('familyName','').lower(),
                u.get('primaryEmail','').split('@')[0].lower()
            ])
            return all(tok in parts for tok in rest)
        studs=[u for u in studs if match(u)]
    return jsonify([{'label':f"{u['name'].get('givenName')} {u['name'].get('familyName')}",
                     'value':u['primaryEmail']} for u in studs])

# ─── AJAX STAFF USER SUGGESTION ────────────────────────────────────
@app.route('/search_staff')
@login_required
@admin_required
def search_staff():
    q = request.args.get('q','').strip()
    if not q:
        return jsonify([])

    # build Directory API client
    creds = service_account.Credentials.from_service_account_file(
        app.config['SERVICE_ACCOUNT_FILE'],
        scopes=[
            'https://www.googleapis.com/auth/admin.directory.user.readonly'
        ]
    ).with_subject(app.config['ADMIN_USER'])
    svc = build('admin','directory_v1', credentials=creds)

    # initial prefix search
    tokens = q.split()
    found = []
    try:
        for field in ('givenName','familyName','email'):
            resp = svc.users().list(
                customer='my_customer',
                query=f"{field}:{tokens[0]}*",
                maxResults=50
            ).execute()
            found.extend(resp.get('users',[]))
    except HttpError:
        return jsonify([]), 500

    # dedupe by email
    unique = {u['primaryEmail']: u for u in found if u.get('primaryEmail')}

    # only staff OU
    staff_prefixes = [
        '/Staff/District',
        '/Staff/Faculty',
        '/Staff/Long Term Subs',
        '/Staff/School Admins'
    ]
    staff = [
        u for u in unique.values()
        if any(u.get('orgUnitPath','').startswith(pref) for pref in staff_prefixes)
    ]

    # multi-token filter (if more words)
    if len(tokens) > 1:
        rest = [t.lower() for t in tokens[1:]]
        def match(u):
            parts = " ".join([
                u['name'].get('givenName','').lower(),
                u['name'].get('familyName','').lower(),
                u.get('primaryEmail','').split('@')[0].lower()
            ])
            return all(tok in parts for tok in rest)
        staff = [u for u in staff if match(u)]

    # return label/value pairs
    return jsonify([
        {
            'label': f"{u['name'].get('givenName','')} {u['name'].get('familyName','')} — {u['primaryEmail']}",
            'value': u['primaryEmail']
        }
        for u in staff
    ])


# ─── MISC PAGES ─────────────────────────────────────────────────────
@app.route('/help')
def help_page(): return render_template('help.html')
@app.route('/instructions')
@login_required
def instructions_page(): return render_template('instructions.html',user=session['user_info'])
@app.route('/documentation')
@login_required
def documentation_page(): return render_template('documentation.html',user=session['user_info'])
@app.route('/updates')
@login_required
def updates_page(): return render_template('updates.html',user=session['user_info'])

# ─── Admin Dashboard ────────────────────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin_page():
    user = session['user_info']
    start, end = request.args.get('start_date'), request.args.get('end_date')
    def in_range(ts):
        dt=datetime.fromisoformat(ts)
        if start and dt<datetime.fromisoformat(start): return False
        if end   and dt>datetime.fromisoformat(end):   return False
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
    email=request.form['email'].strip().lower()
    admins=load_admins()
    if email in admins:
        flash(f"{email} exists.", "warning")
    else:
        admins.append(email); save_admins(admins)
        flash(f"Added {email}", "success")
    return redirect(url_for('admin_page'))

@app.route('/remove_admin', methods=['POST'])
@login_required
@admin_required
def remove_admin():
    email=request.form['email'].strip().lower()
    admins=load_admins()
    if email not in admins:
        flash(f"{email} missing.","warning")
    elif email==session['user_info']['email'].lower():
        flash("Can't remove yourself.","danger")
    else:
        admins.remove(email); save_admins(admins)
        flash(f"Removed {email}","success")
    return redirect(url_for('admin_page'))

# ─── Approve / Deny Reset Requests ──────────────────────────────────
@app.route('/approve_request', methods=['POST'])
@login_required
@admin_required
def approve_request():
    rid=request.form['id']; reqs=load_requests()
    for r in reqs:
        if r['id']==rid:
            r['status']='Approved'
            flash(f"Approved {rid}", "success"); break
    save_requests(reqs)
    return redirect(url_for('admin_page'))

@app.route('/deny_request', methods=['POST'])
@login_required
@admin_required
def deny_request():
    rid=request.form['id']; reqs=load_requests()
    for r in reqs:
        if r['id']==rid:
            r['status']='Denied'
            flash(f"Denied {rid}", "info"); break
    save_requests(reqs)
    return redirect(url_for('admin_page'))

# ─── Error handlers ─────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e): return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
