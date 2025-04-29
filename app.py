import os
import sys
import json
import logging
import secrets
import string
import io, csv
import math
import requests
import os, random, csv
from datetime import datetime, date
from functools import wraps
from flask_mail import Mail, Message
from flask import Response

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
ADMIN_FILE    = os.path.join(app.root_path, 'static', 'data', 'admin_users.json')
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
    with open(ADMIN_FILE, encoding='utf-8') as f:
        return json.load(f)

def save_admins(admins):
    with open(ADMIN_FILE, 'w', encoding='utf-8') as f:
        json.dump(admins, f, indent=2)

def get_admin_role(email):
    """Returns 'superadmin' or 'admin' or None."""
    email = email.lower()
    for u in load_admins():
        if u['email'].lower() == email:
            return u.get('role')
    return None


def load_requests():
    return load_json(REQUESTS_FILE)

def save_requests(reqs):
    save_json(REQUESTS_FILE, reqs)

POLICY_FILE = os.path.join(app.root_path, 'static', 'data', 'policy.json')

def load_policy():
    if not os.path.exists(POLICY_FILE):
        # if you want defaults instead of an empty file
        return {
          "secure_workflow": False,
          "bulk_reset":      False,
          "custom_policy":   False,
          "min_length":      8,
          "complexity":      "med",
            "reset_limit": RESET_LIMIT
        }
    with open(POLICY_FILE, encoding='utf-8') as f:
        return json.load(f)

def save_policy(policy_dict):
    with open(POLICY_FILE, 'w', encoding='utf-8') as f:
        json.dump(policy_dict, f, indent=2)

# ─── Helpers ────────────────────────────────────────────────────────
def generate_password(length=8):
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

        if not any(u['email'].lower() == email for u in admins):
            abort(403)
        return f(*args, **kwargs)
    return decorated

def superadmin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        role = get_admin_role(session['user_info']['email'])
        if role != 'superadmin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


QUOTES_CSV = os.path.join(app.root_path, 'static', 'data', 'quotes.csv')

def load_local_quotes():
    quotes = []
    try:
        with open(QUOTES_CSV, encoding='utf-8') as f:
            # adjust fieldnames to match your CSV headers:
            reader = csv.DictReader(f)
            for row in reader:
                # Gist uses "quote" and "author" headers
                content = row.get('quote') or row.get('Quote')
                author  = row.get('author') or row.get('Author')
                if content and author:
                    quotes.append((content.strip(), author.strip()))
    except FileNotFoundError:
        pass
    return quotes

LOCAL_QUOTES = load_local_quotes()

if not LOCAL_QUOTES:
    LOCAL_QUOTES = [
        ("Keep going—you’re doing great!", "ResetApp"),
    ]
@app.context_processor
def inject_helpers():
    # make get_admin_role (and any other helpers) available in all templates
    return {
        'get_admin_role': get_admin_role
    }
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


# SMTP configuration (you exported these as env vars earlier)
app.config.update(
    MAIL_SERVER        = os.environ.get("MAIL_SERVER",   "smtp.gmail.com"),
    MAIL_PORT          = int(os.environ.get("MAIL_PORT",  587)),
    MAIL_USE_TLS       = True,
    MAIL_USERNAME      = os.environ["MAIL_USERNAME"],       # e.g. noreply@hart.k12.ga.us
    MAIL_PASSWORD      = os.environ["MAIL_PASSWORD"],       # your 16-char App Password
    MAIL_DEFAULT_SENDER= ("ResetApp NoReply", os.environ["MAIL_USERNAME"])
)

mail = Mail(app)


def send_password_reset_email(student_email, student_name, new_password):
    subject = f"{student_name} — Your ResetApp Password"
    body = f"""\
Hello {student_name},

Your Google Workspace account password has just been reset via ResetApp.

New  password: {new_password}

Please sign in immediately.

If you did not request this change, contact your media specialist right away.

Thanks,
ResetApp Team
"""
    msg = Message(subject=subject, recipients=[student_email], body=body)
    mail.send(msg)
# ─── MAIN APP with RESET LIMIT ───────────────────────────────────────

RESET_LIMIT = 5

@app.route('/', methods=['GET','POST'])
@login_required
def index():
    user_info = session['user_info']
    today = date.today().isoformat()
    done = sum(1 for a in audit_logs
               if a.get('admin') == user_info['email']
               and a['timestamp'].startswith(today)
               and a.get('outcome') == 'Success'
    )

    new_pw = None
    se     = None
    sn     = None
    outcome = ''

    if request.method == 'POST':
        if done >= RESET_LIMIT:
            flash("Daily limit reached.", "danger")
            flash("Request more <a href='/request_more'>here</a>.", "info")
        else:
            se = request.form.get('student_email','').strip()
            sn = request.form.get('student_name','').strip()

            if not se:
                flash('Enter a student email.', 'danger')
                outcome = 'Canceled'

            else:
                # build your Directory API client
                creds = (
                  service_account.Credentials
                    .from_service_account_file(
                      app.config['SERVICE_ACCOUNT_FILE'],
                      scopes=['https://www.googleapis.com/auth/admin.directory.user']
                    )
                    .with_subject(app.config['ADMIN_USER'])
                )
                svc = build('admin','directory_v1',credentials=creds)

                try:
                    # fetch teacher & student records
                    teacher = svc.users().get(userKey=user_info['email']).execute()
                    student = svc.users().get(userKey=se).execute()

                    # OU checks
                    if not student.get('orgUnitPath','').startswith('/Students'):
                        flash("Only student OU allowed.", 'danger')
                        outcome='Denied'

                    elif teacher.get('orgUnitPath') != student.get('orgUnitPath'):
                        flash("No permission for that OU.", 'danger')
                        outcome='Denied'

                    else:
                        # generate & apply new password
                        new_pw = generate_password(8)
                        svc.users().update(
                          userKey=se,
                          body={
                            'password': new_pw,
                            'changePasswordAtNextLogin': false
                          }
                        ).execute()
                        send_password_reset_email(se, sn or se, new_pw)

                        # ── SEND THE “NOREPLY” EMAIL ─────────────────────
                        subject = f"{sn} — Your ResetApp Password"
                        body = f"""Hello {sn},

Your password has been reset by our staff.  Your new password is:

    {new_pw}


If you did not request this reset, please contact media center immediately.

– The ResetApp Team
"""
                        try:
                            msg = Message(subject=subject,
                                          recipients=[se],
                                          body=body)
                            mail.send(msg)
                            flash(f'Password reset and emailed to {se}', 'success')
                        except Exception as e:
                            app.logger.error("Email send failed: %s", e)
                            flash('Password reset — but email failed to send.', 'warning')
                        # ────────────────────────────────────────────────

                        outcome='Success'

                except Exception as e:
                    app.logger.error("Reset error", exc_info=True)
                    flash(f'Error during reset: {e}', 'danger')
                    outcome='Error'

            # audit log entry
            audit_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'admin':     user_info['email'],
                'student':   f"{se} ({sn})" if sn else se,
                'outcome':   outcome
            })
    quote_content = None
    quote_author = None

    # Pick a random local quote
    quote_content, quote_author = random.choice(LOCAL_QUOTES)

    return render_template(
        'index.html',
        user=user_info,
        new_password=new_pw,
        student_email=se,
        student_name=sn,
        quote_content=quote_content,
        quote_author=quote_author
    )
@app.route('/test-email')
def test_email():
    msg = Message("Test", recipients=['jordan.hicks@hart.k12.ga.us','evan.ayers@hart.k12.ga.us'])
    msg.body = "If you got this, SMTP is configured!"
    mail.send(msg)
    return "Sent!"

# ─── Request more resets ─────────────────────────────────────────────
@app.route('/request_more')
@login_required
def request_more():
    reqs = load_requests()
    rid = secrets.token_hex(4)
    me = session['user_info']['email']
    today_str = date.today().isoformat()
    reqs.append({
        'id':    rid,
        'email': me,
        'date':  today_str,
        'status':'Pending'
    })
    save_requests(reqs)

    # Notify superadmins & admins by email
    admins = load_admins()
    admin_emails = [u['email'] for u in admins]
    link = url_for('admin_page', _external=True) + '#requests'

    subject = "🔔 ResetApp: Extra-Reset Request Pending"
    body = f"""\
Hello Admin team,

User {me} has requested extra daily resets.

Request ID: {rid}
Date:       {today_str}

You can approve or deny it here:
{link}

Thanks,
ResetApp
"""
    msg = Message(subject, recipients=admin_emails, body=body)
    mail.send(msg)

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
@app.route('/quote')
@login_required
def quote_api():
    import requests
    r = requests.get('https://api.quotable.io/random?tags=motivational|inspirational', timeout=2)
    if r.ok:
        return jsonify(r.json())
    return jsonify({
        "content": "Keep going, you’re doing great!",
        "author": "ResetApp"
    })
# ─── Admin Dashboard ────────────────────────────────────────────────
PAGE_SIZE = 20

@app.route('/admin')
@login_required
@admin_required
def admin_page():
    user = session['user_info']
    start = request.args.get('start_date')
    end   = request.args.get('end_date')

    # Helper to test if a timestamp is in the date range
    def in_range(ts):
        dt = datetime.fromisoformat(ts)
        if start and dt < datetime.fromisoformat(start): return False
        if end   and dt > datetime.fromisoformat(end):   return False
        return True

    # Pull page numbers (default to 1)
    try:
        audit_page = max(1, int(request.args.get('audit_page', 1)))
    except ValueError:
        audit_page = 1
    try:
        login_page = max(1, int(request.args.get('login_page', 1)))
    except ValueError:
        login_page = 1

    # Filter the full logs by date
    filtered_audit = [a for a in audit_logs if in_range(a['timestamp'])]
    filtered_login = [l for l in login_logs if in_range(l['timestamp'])]

    # Pagination helper
    def paginate(items, page):
        total_pages = max(1, math.ceil(len(items) / PAGE_SIZE))
        page = min(max(page, 1), total_pages)
        start_idx = (page - 1) * PAGE_SIZE
        return items[start_idx:start_idx + PAGE_SIZE], page, total_pages

    audit_logs_paginated, audit_page, audit_total_pages = paginate(filtered_audit, audit_page)
    login_logs_paginated, login_page, login_total_pages = paginate(filtered_login, login_page)

    # --- Analytics aggregation ---
    from collections import defaultdict
    reset_by_day = defaultdict(lambda: {'Success': 0, 'Error': 0})
    login_by_day = defaultdict(lambda: {'Success': 0, 'Error': 0})

    # Build daily counts
    for a in audit_logs:
        if not in_range(a['timestamp']): continue
        day = a['timestamp'][:10]
        outcome = a['outcome']
        key = 'Success' if outcome == 'Success' else 'Error'
        reset_by_day[day][key] += 1

    for l in login_logs:
        if not in_range(l['timestamp']): continue
        day = l['timestamp'][:10]
        outcome = l['outcome']
        key = 'Success' if outcome == 'Success' else 'Error'
        login_by_day[day][key] += 1

    days = sorted(reset_by_day.keys())
    reset_success = [reset_by_day[d]['Success'] for d in days]
    reset_error   = [reset_by_day[d]['Error']   for d in days]
    login_success = [login_by_day[d]['Success'] for d in days]
    login_error   = [login_by_day[d]['Error']   for d in days]

    # Recent errors (last 10)
    error_logs = [a for a in audit_logs if a['outcome'] not in ('Success','Approved','Denied')]
    error_logs = error_logs[-10:]

    # Other tabs
    admin_users   = load_admins()
    requests_list = load_requests()
    policy        = load_policy()

    return render_template('admin.html',
        user                   = user,
        # paginated audit
        audit_logs_paginated   = audit_logs_paginated,
        audit_page             = audit_page,
        audit_total_pages      = audit_total_pages,
        # paginated login
        login_logs_paginated   = login_logs_paginated,
        login_page             = login_page,
        login_total_pages      = login_total_pages,
        # analytics variables
        days                   = days,
        reset_success          = reset_success,
        reset_error            = reset_error,
        login_success          = login_success,
        login_error            = login_error,
        error_logs             = error_logs,
        # other tabs
        admin_users            = admin_users,
        requests_list          = requests_list,
        get_admin_role         = get_admin_role,
        policy                 = policy
    )

# ─── Add / Remove / Change Admin ──────────────────────────────────────
@app.route('/add_admin', methods=['POST'])
@login_required
@superadmin_required
def add_admin():
    email = request.form['email'].strip().lower()
    role  = request.form.get('role', 'admin')
    admins = load_admins()
    if any(u['email'].lower() == email for u in admins):
        flash(f"{email} already exists.", "warning")
    else:
        admins.append({"email": email, "role": role})
        save_admins(admins)
        flash(f"Added {role}: {email}", "success")
    return redirect(url_for('admin_page') + '#manage_admins')

@app.route('/remove_admin', methods=['POST'])
@login_required
@superadmin_required
def remove_admin():
    email = request.form['email'].strip().lower()
    you   = session['user_info']['email'].lower()
    if email == you:
        flash("You can’t remove yourself.", "danger")
    else:
        admins = load_admins()
        new_list = [u for u in admins if u['email'].lower() != email]
        if len(new_list) == len(admins):
            flash(f"{email} not found.", "warning")
        else:
            save_admins(new_list)
            flash(f"Removed {email}", "success")
    return redirect(url_for('admin_page') + '#manage_admins')

@app.route('/change_admin_role', methods=['POST'])
@login_required
@superadmin_required
def change_admin_role():
    email    = request.form['email'].strip().lower()
    new_role = request.form.get('role')
    admins   = load_admins()
    for u in admins:
        if u['email'].lower() == email:
            u['role'] = new_role
            save_admins(admins)
            flash(f"Changed {email} to {new_role}", "success")
            break
    else:
        flash(f"{email} not found.", "warning")
    return redirect(url_for('admin_page') + '#manage_admins')

from collections import Counter, defaultdict
@app.route('/analytics')
@login_required
@superadmin_required
def analytics_page():
    # Date range (optional)
    start = request.args.get('start_date')
    end   = request.args.get('end_date')
    def in_range(ts):
        dt = datetime.fromisoformat(ts)
        if start and dt < datetime.fromisoformat(start): return False
        if end   and dt > datetime.fromisoformat(end):   return False
        return True

    # Aggregate resets: success vs error by day
    reset_by_day = defaultdict(lambda: {'Success':0,'Error':0})
    for a in audit_logs:
        if not in_range(a['timestamp']): continue
        day = a['timestamp'][:10]
        reset_by_day[day][a['outcome']] += 1

    # Aggregate logins: total attempts by day and outcome
    login_by_day = defaultdict(lambda: {'Success':0,'Error':0})
    for l in login_logs:
        if not in_range(l['timestamp']): continue
        day = l['timestamp'][:10]
        login_by_day[day][l['outcome']] += 1

    # Error log sample: filter audit_logs with outcome != 'Success'
    errors = [a for a in audit_logs if a['outcome'] not in ('Success','Approved','Denied')]

    # Sort days
    days = sorted(reset_by_day.keys())

    return render_template('analytics.html',
        days=days,
        reset_success=[reset_by_day[d]['Success'] for d in days],
        reset_error=[reset_by_day[d]['Error']   for d in days],
        login_success=[login_by_day[d]['Success'] for d in days],
        login_error=[login_by_day[d]['Error']   for d in days],
        error_logs=errors
    )

@app.route('/changelog')
@login_required
def changelog_page():
    # locate the JSON file (adjust path as needed)
    data_path = os.path.join(app.root_path, 'static', 'data', 'changelog.json')
    with open(data_path, encoding='utf-8') as f:
        versions = json.load(f)

    return render_template(
        'changelog.html',
        user=session.get('user_info'),
        versions=versions
    )
# ─── Super-Admin Settings Save ───────────────────────────────────────
# New unified save_settings
@app.route('/save_settings', methods=['POST'])
@login_required
@superadmin_required
def save_settings():
    policy = load_policy()
    # toggles
    policy['secure_workflow'] = bool(request.form.get('secure_workflow'))
    policy['bulk_reset']      = bool(request.form.get('bulk_reset'))
    policy['custom_policy']   = bool(request.form.get('custom_policy'))
    # numeric
    min_len = request.form.get('min_length')
    if min_len and min_len.isdigit(): policy['min_length'] = int(min_len)
    # complexity
    comp = request.form.get('complexity')
    if comp in ('low','med','high'): policy['complexity'] = comp
    rl = request.form.get('reset_limit')
    if rl and rl.isdigit():
        policy['reset_limit'] = int(rl)
    save_policy(policy)
    flash("Settings updated.", "success")
    return redirect(url_for('admin_page'))

# Export audit CSV
@app.route('/export_audit')
@login_required
@admin_required
def export_audit():
    start, end = request.args.get('start_date'), request.args.get('end_date')
    def in_range(ts):
        dt = datetime.fromisoformat(ts)
        if start and dt < datetime.fromisoformat(start): return False
        if end   and dt > datetime.fromisoformat(end):   return False
        return True
    rows = [a for a in audit_logs if in_range(a['timestamp'])]
    def gen():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['Timestamp','Admin','Student','Outcome'])
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for a in rows:
            writer.writerow([a['timestamp'],a['admin'],a['student'],a['outcome']])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)
    return Response(gen(), headers={
      'Content-Disposition': 'attachment; filename="audit_logs.csv"',
      'Content-Type': 'text/csv'
    })

@app.route('/export_login')
@login_required
@admin_required
def export_login():
    start = request.args.get('start_date')
    end   = request.args.get('end_date')
    def in_range(ts):
        dt = datetime.fromisoformat(ts)
        if start and dt < datetime.fromisoformat(start): return False
        if end   and dt > datetime.fromisoformat(end):   return False
        return True

    rows = [l for l in login_logs if in_range(l['timestamp'])]
    def gen():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['Timestamp','User','Outcome'])
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for l in rows:
            writer.writerow([l['timestamp'],l['user'],l['outcome']])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)

    return Response(gen(), headers={
      'Content-Disposition': 'attachment; filename="login_logs.csv"',
      'Content-Type': 'text/csv'
    })

# Download example CSV
@app.route('/download_example_csv')
@login_required
@admin_required
def download_example_csv():
    data = 'email\nstudent1@hart.k12.ga.us\nstudent2@hart.k12.ga.us\n'
    return Response(data, headers={
      'Content-Disposition': 'attachment; filename="bulk_reset_template.csv"',
      'Content-Type': 'text/csv'
    })

# Bulk reset handler
@app.route('/bulk_reset', methods=['POST'])
@login_required
@superadmin_required
def bulk_reset():
    f = request.files.get('csv_file')
    if not f:
        flash("No CSV uploaded.", "danger")
        return redirect(url_for('admin_page') + "#bulkreset")
    try:
        txt = f.stream.read().decode('utf-8')
        rows = list(csv.reader(io.StringIO(txt)))
    except Exception:
        flash("Could not read CSV (check encoding).", "danger")
        return redirect(url_for('admin_page') + "#bulkreset")
    if rows and rows[0][0].lower() == 'email': rows = rows[1:]
    count = 0
    poli = load_policy()
    for row in rows:
        email = row[0].strip()
        if not email: continue
        new_pw = generate_password(poli.get('min_length',8))
        audit_logs.append({
          'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
          'admin':     session['user_info']['email'],
          'student':   email,
          'outcome':   'Bulk Reset'
        })
        count += 1
    flash(f"Bulk reset complete for {count} accounts.", "success")
    return redirect(url_for('admin_page') + "#bulkreset")
# ─── Approve / Deny Reset Requests ──────────────────────────────────
@app.route('/approve_request', methods=['POST'])
@login_required
@admin_required
def approve_request():
    rid = request.form['id']
    reqs = load_requests()
    requester = None

    # 1) Update request status
    for r in reqs:
        if r['id'] == rid:
            r['status'] = 'Approved'
            requester = r['email']
            flash(f"Approved {rid}", "success")
            break
    save_requests(reqs)

    # 2) Email the requester
    if requester:
        subject = "✅ ResetApp: Your Extra-Reset Request Approved"
        body = f"""\
Hello,

Your request for extra daily resets (ID: {rid}) has been **approved**.

You may now perform additional resets today.

Thanks,
ResetApp Team
"""
        msg = Message(subject, recipients=[requester], body=body)
        mail.send(msg)

    # 3) Broadcast to all other admins
    acting = session['user_info']['email']
    admins = [u['email'] for u in load_admins() if u['email'] != acting]
    if admins:
        subject = f"🔔 Request {rid} Approved by {acting}"
        body = f"""\
Hello Admin team,

{acting} has approved extra-reset request **{rid}** for user **{requester}**.

You can review all requests here:
{url_for('admin_page', _external=True)}#requests

Thanks,
ResetApp
"""
        msg = Message(subject, recipients=admins, body=body)
        mail.send(msg)

    return redirect(url_for('admin_page') + '#requests')


@app.route('/deny_request', methods=['POST'])
@login_required
@admin_required
def deny_request():
    rid = request.form['id']
    reqs = load_requests()
    requester = None

    # 1) Update request status
    for r in reqs:
        if r['id'] == rid:
            r['status'] = 'Denied'
            requester = r['email']
            flash(f"Denied {rid}", "info")
            break
    save_requests(reqs)

    # 2) Email the requester
    if requester:
        subject = "❌ ResetApp: Your Extra-Reset Request Denied"
        body = f"""\
Hello,

Your request for extra daily resets (ID: {rid}) has been **denied**.

If you have questions, please contact your administrator.

Thanks,
ResetApp Team
"""
        msg = Message(subject, recipients=[requester], body=body)
        mail.send(msg)

    # 3) Broadcast to all other admins
    acting = session['user_info']['email']
    admins = [u['email'] for u in load_admins() if u['email'] != acting]
    if admins:
        subject = f"🔔 Request {rid} Denied by {acting}"
        body = f"""\
Hello Admin team,

{acting} has denied extra-reset request **{rid}** for user **{requester}**.

You can review all requests here:
{url_for('admin_page', _external=True)}#requests

Thanks,
ResetApp
"""
        msg = Message(subject, recipients=admins, body=body)
        mail.send(msg)

    return redirect(url_for('admin_page') + '#requests')

# ─── Error handlers ─────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e): return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
