import logging
import math
import os
import secrets
from datetime import date, datetime

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from googleapiclient.errors import HttpError
from werkzeug.utils import secure_filename

from auth import login_required, role_required
from services.classroom import get_teacher_roster_emails
from services.google_admin import get_user, update_password, search_users
from services.roles import (
    ROLE_TEACHER,
    ROLE_MEDIA_SPECIALIST,
    ROLE_ADMIN,
    ROLE_GLOBAL_ADMIN,
    get_school_from_ou
)
from services.storage import (
    get_audit_logs,
    load_requests,
    save_requests,
    load_app_settings,
    set_theme_for_user,
    add_bug_report,
    log_audit_event,
    get_classroom_sync,
    set_classroom_sync,
    load_known_issues
)

logger = logging.getLogger(__name__)

bp = Blueprint('main', __name__)


@bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('auth.login_page'))

    settings = load_app_settings()
    require_request = _truthy(settings.get('require_reset_request', 'true'))
    cooldown_minutes = _safe_int(settings.get('reset_cooldown_minutes', 0), 0)
    if cooldown_minutes < 0:
        cooldown_minutes = 0

    today = date.today().isoformat()
    done = 0
    last_reset_at = None
    for entry in get_audit_logs():
        if entry.get('admin') != user_info['email']:
            continue
        if entry.get('outcome') != 'Success':
            continue
        if entry.get('action_type') != 'password_reset':
            continue
        timestamp = entry.get('timestamp', '')
        if timestamp.startswith(today):
            done += 1
        parsed = _parse_timestamp(timestamp)
        if parsed and (last_reset_at is None or parsed > last_reset_at):
            last_reset_at = parsed

    new_pw = None
    request_more_url = None
    se = sn = outcome = ''

    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            abort(403)

        role = session.get('role')
        if role not in (ROLE_ADMIN, ROLE_GLOBAL_ADMIN) and cooldown_minutes:
            remaining = _cooldown_remaining(last_reset_at, cooldown_minutes)
            if remaining:
                wait_minutes = max(1, math.ceil(remaining / 60))
                flash(f'Please wait {wait_minutes} minute(s) before another reset.', 'warning')
                outcome = 'Cooldown'

        if not outcome:
            limit_reached = (
                role not in (ROLE_ADMIN, ROLE_GLOBAL_ADMIN)
                and done >= current_app.config.get('RESET_LIMIT', 5)
            )
            if limit_reached and require_request and not _has_approved_request(user_info['email'], today):
                flash('Daily limit reached.', 'danger')
                request_more_url = url_for('main.request_more', token=session.get('csrf_token'))
                outcome = 'Limit Reached'
            else:
                se = request.form.get('student_email', '').strip().lower()
                sn = request.form.get('student_name', '').strip()
                if not se:
                    flash('Enter a student email.', 'danger')
                    outcome = 'Canceled'
                else:
                    try:
                        student = get_user(se)
                        if not _is_student_account(student):
                            flash('Only student accounts.', 'danger')
                            outcome = 'Denied'
                        elif not _can_reset_student(role, student, user_info['email']):
                            flash('No permission.', 'danger')
                            outcome = 'Denied'
                        else:
                            new_pw = _generate_password(12)
                            update_password(se, new_pw)
                            flash('Password reset!', 'success')
                            outcome = 'Success'
                    except Exception as exc:
                        logger.error('Reset error', exc_info=True)
                        flash(f'Error: {exc}', 'danger')
                        outcome = 'Error'

        log_audit_event(
            admin_email=user_info['email'],
            outcome=outcome,
            detail=f"{se} ({sn})" if sn else se,
            role=session.get('role'),
            action_type='password_reset',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )

    known_issues = load_known_issues()
    global_issues = [
        issue for issue in known_issues
        if issue.get('status') == 'Active' and issue.get('level') == 'global'
    ]

    return render_template(
        'index.html',
        user=user_info,
        new_password=new_pw,
        student_email=se,
        student_name=sn,
        role=session.get('role'),
        request_more_url=request_more_url,
        classroom_sync=get_classroom_sync(user_info['email']),
        known_issues=known_issues,
        global_issues=global_issues
    )


@bp.route('/request_more')
@login_required
def request_more():
    token = request.args.get('token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    settings = load_app_settings()
    if not _truthy(settings.get('require_reset_request', 'true')):
        flash('Reset requests are disabled.', 'info')
        return redirect(url_for('main.index'))
    reqs = load_requests()
    today = date.today().isoformat()
    addr = session['user_info']['email'].lower()
    for req in reqs:
        if req.get('email') == addr and req.get('date') == today and req.get('status') in ('Pending', 'Approved'):
            flash('Request already submitted for today.', 'info')
            return redirect(url_for('main.index'))
    rid = secrets.token_hex(4)
    reqs.append({
        'id': rid,
        'email': addr,
        'date': today,
        'status': 'Pending'
    })
    save_requests(reqs)
    flash('Request submitted.', 'success')
    return redirect(url_for('main.index'))


@bp.route('/theme', methods=['POST'])
@login_required
def set_theme():
    data = request.get_json(silent=True) or {}
    theme = data.get('theme') or request.form.get('theme')
    if theme not in ('light', 'dark'):
        return jsonify({'ok': False, 'error': 'Invalid theme'}), 400
    session['theme'] = theme
    user = session.get('user_info', {})
    if user.get('email'):
        set_theme_for_user(user['email'], theme)
    return jsonify({'ok': True, 'theme': theme})


@bp.route('/sync_classroom')
@login_required
@role_required({ROLE_TEACHER})
def sync_classroom():
    try:
        roster = get_teacher_roster_emails(session['user_info']['email'])
        set_classroom_sync(session['user_info']['email'], len(roster))
        flash(f'Synced {len(roster)} Classroom students.', 'success')
    except Exception as exc:
        logger.error('Classroom sync error', exc_info=True)
        flash(f'Classroom sync failed: {exc}', 'danger')
    return redirect(url_for('main.index'))


@bp.route('/report-bug', methods=['GET', 'POST'])
@login_required
def report_bug():
    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            abort(403)
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', 'medium').strip()
        page = request.form.get('page', '').strip()

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('report_bug.html', user=session.get('user_info'))

        attachment = _save_bug_attachment(request.files.get('screenshot'))
        if request.files.get('screenshot') and not attachment:
            flash('Unsupported image type. Use PNG, JPG, GIF, or WEBP.', 'danger')
            return render_template('report_bug.html', user=session.get('user_info'))

        add_bug_report({
            'id': secrets.token_hex(4),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reporter': session['user_info']['email'],
            'title': title,
            'description': description,
            'severity': severity,
            'page': page,
            'status': 'Open',
            'attachment': attachment
        })
        flash('Bug report submitted. Thank you!', 'success')
        return redirect(url_for('report_bug_page'))

    return render_template('report_bug.html', user=session.get('user_info'))


def _save_bug_attachment(file_storage):
    if not file_storage or not file_storage.filename:
        return ''
    filename = secure_filename(file_storage.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    allowed = current_app.config.get('ALLOWED_BUG_UPLOADS', set())
    if ext not in allowed:
        return ''
    token = secrets.token_hex(8)
    final_name = f'{token}.{ext}'
    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, final_name)
    file_storage.save(file_path)
    return f'uploads/bug_reports/{final_name}'


@bp.route('/search_users')
@login_required
@role_required({ROLE_ADMIN, ROLE_GLOBAL_ADMIN})
def search_users_route():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])

    try:
        candidates = search_users(q)
    except HttpError:
        return jsonify([]), 500

    uniq = {u['primaryEmail']: u for u in candidates if u.get('primaryEmail')}
    students = [u for u in uniq.values() if _is_student_account(u)]

    toks = q.split()
    if len(toks) > 1:
        rest = [t.lower() for t in toks[1:]]
        def match(u):
            parts = ' '.join([
                u['name'].get('givenName', '').lower(),
                u['name'].get('familyName', '').lower(),
                u['primaryEmail'].split('@')[0].lower()
            ])
            return all(tok in parts for tok in rest)
        students = [u for u in students if match(u)]

    return jsonify([
        {
            'label': f"{u['name'].get('givenName', '')} {u['name'].get('familyName', '')}",
            'value': u['primaryEmail']
        }
        for u in students
    ])


def _is_student_ou(ou_path):
    if not ou_path:
        return False
    prefixes = current_app.config.get('STUDENT_OU_PREFIXES', [])
    for prefix in prefixes:
        if ou_path.startswith(prefix):
            return True
    return False


def _is_student_email(email):
    email = (email or '').lower()
    if not email:
        return False
    domains = current_app.config.get('STUDENT_EMAIL_DOMAINS', [])
    for domain in domains:
        domain = domain.lower().lstrip('@')
        if email.endswith(f'@{domain}'):
            return True
    return False


def _is_student_account(user):
    if not user:
        return False
    return _is_student_ou(user.get('orgUnitPath', '')) or _is_student_email(user.get('primaryEmail', ''))


def _can_reset_student(role, student, teacher_email):
    student_email = student.get('primaryEmail', '').lower()
    if role in (ROLE_ADMIN, ROLE_GLOBAL_ADMIN):
        return True
    if role == ROLE_MEDIA_SPECIALIST:
        staff_school = session.get('school')
        student_school = get_school_from_ou(student.get('orgUnitPath', ''))
        return bool(staff_school) and staff_school == student_school
    if role == ROLE_TEACHER:
        roster = get_teacher_roster_emails(teacher_email)
        return student_email in roster
    return False


def _generate_password(length=12):
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _parse_timestamp(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None


def _cooldown_remaining(last_reset_at, cooldown_minutes):
    if not last_reset_at or cooldown_minutes <= 0:
        return 0
    elapsed = (datetime.now() - last_reset_at).total_seconds()
    cooldown_seconds = max(0, int(cooldown_minutes) * 60)
    return max(0, int(cooldown_seconds - elapsed))


def _has_approved_request(email, request_date):
    addr = (email or '').lower()
    for req in load_requests():
        if req.get('email') == addr and req.get('date') == request_date:
            if str(req.get('status', '')).lower() == 'approved':
                return True
    return False


def _truthy(value):
    return str(value).strip().lower() in ('1', 'true', 'yes', 'y', 'on')


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
