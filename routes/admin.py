import io
import json
import logging
import secrets
import zipfile
from datetime import datetime, timedelta

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from googleapiclient.errors import HttpError

from auth import login_required, admin_required, role_required
from services.google_admin import search_staff
from services.roles import ROLE_GLOBAL_ADMIN
from services.storage import (
    get_audit_logs,
    get_login_logs,
    load_admins,
    save_admins,
    load_global_admins,
    save_global_admins,
    load_requests,
    save_requests,
    load_app_settings,
    set_app_settings,
    load_bug_reports,
    load_known_issues,
    add_known_issue as add_known_issue_record,
    update_known_issue,
    delete_known_issue,
    log_audit_event,
    update_bug_report,
    prune_audit_logs
)

logger = logging.getLogger(__name__)

bp = Blueprint('admin', __name__)

def _admin_context(section, **kwargs):
    context = {
        'user': session.get('user_info'),
        'admin_section': section,
    }
    context.update(kwargs)
    return context


def _in_date_range(ts, start, end):
    dt = datetime.fromisoformat(ts)
    if start and dt < datetime.fromisoformat(start):
        return False
    if end and dt > datetime.fromisoformat(end):
        return False
    return True


def _audit_matches(entry, audit_role, audit_school, audit_ou):
    if audit_role and entry.get('role') != audit_role:
        return False
    if audit_school and (entry.get('admin_school') or '').lower() != audit_school.lower():
        return False
    if audit_ou and audit_ou not in (entry.get('admin_ou') or ''):
        return False
    return True


def _filter_audit_logs(start, end, audit_role, audit_school, audit_ou):
    return [
        entry
        for entry in get_audit_logs()
        if _in_date_range(entry['timestamp'], start, end)
        and _audit_matches(entry, audit_role, audit_school, audit_ou)
    ]


def _filter_login_logs(start, end):
    return [
        entry
        for entry in get_login_logs()
        if _in_date_range(entry['timestamp'], start, end)
    ]


@bp.route('/admin')
@login_required
@admin_required
def admin_page():
    return redirect(url_for('admin.admin_audit'))


@bp.route('/admin/audit')
@login_required
@admin_required
def admin_audit():
    start = request.args.get('start_date')
    end = request.args.get('end_date')
    audit_role = request.args.get('audit_role', '').strip()
    audit_school = request.args.get('audit_school', '').strip()
    audit_ou = request.args.get('audit_ou', '').strip()
    audit_logs = _filter_audit_logs(start, end, audit_role, audit_school, audit_ou)
    return render_template(
        'admin_audit.html',
        **_admin_context('audit', audit_logs=audit_logs)
    )


@bp.route('/admin/logins')
@login_required
@admin_required
def admin_logins():
    start = request.args.get('start_date')
    end = request.args.get('end_date')
    login_logs = _filter_login_logs(start, end)
    return render_template(
        'admin_logins.html',
        **_admin_context('logins', login_logs=login_logs)
    )


@bp.route('/admin/students')
@login_required
@admin_required
def admin_students():
    return render_template('admin_students.html', **_admin_context('students'))


@bp.route('/admin/admins')
@login_required
@admin_required
def admin_admins():
    return render_template(
        'admin_admins.html',
        **_admin_context('admins', admin_users=load_admins(), global_admins=load_global_admins())
    )


@bp.route('/admin/requests')
@login_required
@admin_required
def admin_requests():
    return render_template(
        'admin_requests.html',
        **_admin_context('requests', requests_list=load_requests())
    )


@bp.route('/admin/bugs')
@login_required
@admin_required
def admin_bugs():
    return render_template(
        'admin_bugs.html',
        **_admin_context('bugs', bug_reports=load_bug_reports())
    )


@bp.route('/admin/known-issues')
@login_required
@admin_required
def admin_known_issues():
    return render_template(
        'admin_known_issues.html',
        **_admin_context('known_issues', known_issues=load_known_issues())
    )


@bp.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@role_required({ROLE_GLOBAL_ADMIN})
def admin_settings():
    settings = load_app_settings()
    require_request = str(settings.get('require_reset_request', 'true')).lower() in ('1', 'true', 'yes', 'on')
    cooldown_raw = settings.get('reset_cooldown_minutes', '0')
    try:
        cooldown_minutes = int(cooldown_raw)
    except (TypeError, ValueError):
        cooldown_minutes = 0

    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            abort(403)
        require_request = request.form.get('require_reset_request') == 'on'
        cooldown_raw = request.form.get('reset_cooldown_minutes', '').strip()
        try:
            cooldown_minutes = int(cooldown_raw)
        except (TypeError, ValueError):
            flash('Cooldown must be a whole number of minutes.', 'danger')
            return redirect(url_for('admin.admin_settings'))
        if cooldown_minutes < 0 or cooldown_minutes > 1440:
            flash('Cooldown must be between 0 and 1440 minutes.', 'danger')
            return redirect(url_for('admin.admin_settings'))

        set_app_settings({
            'require_reset_request': 'true' if require_request else 'false',
            'reset_cooldown_minutes': str(cooldown_minutes)
        })
        flash('Settings updated.', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Admin Settings Updated',
            detail=f"require_reset_request={require_request}, cooldown_minutes={cooldown_minutes}",
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
        return redirect(url_for('admin.admin_settings'))

    return render_template(
        'admin_settings.html',
        **_admin_context(
            'settings',
            require_request=require_request,
            cooldown_minutes=cooldown_minutes,
            reset_limit=current_app.config.get('RESET_LIMIT', 5)
        )
    )


@bp.route('/audit/export')
@login_required
@admin_required
def export_audit_csv():
    start = request.args.get('start_date')
    end = request.args.get('end_date')
    audit_role = request.args.get('audit_role', '').strip()
    audit_school = request.args.get('audit_school', '').strip()
    audit_ou = request.args.get('audit_ou', '').strip()
    rows = _filter_audit_logs(start, end, audit_role, audit_school, audit_ou)
    header = ['timestamp', 'admin', 'role', 'school', 'action', 'details', 'admin_ou']
    lines = [','.join(header)]
    for r in rows:
        lines.append(','.join([
            r.get('timestamp', ''),
            r.get('admin', ''),
            r.get('role', ''),
            r.get('admin_school', ''),
            r.get('outcome', ''),
            (r.get('student', '') or '').replace(',', ' '),
            r.get('admin_ou', '')
        ]))

    csv_data = '\n'.join(lines)
    return current_app.response_class(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=audit_logs.csv'}
    )


@bp.route('/admin/export')
@login_required
@admin_required
def export_data():
    payloads = {
        'audit_logs.json': get_audit_logs(),
        'bug_reports.json': load_bug_reports(),
        'known_issues.json': load_known_issues()
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, data in payloads.items():
            zf.writestr(name, json.dumps(data, indent=2))
    buf.seek(0)
    log_audit_event(
        admin_email=session['user_info']['email'],
        outcome='Data Exported',
        detail='audit_logs + bug_reports + known_issues',
        role=session.get('role'),
        action_type='admin_action',
        admin_ou=session.get('orgUnitPath'),
        admin_school=session.get('school')
    )
    return current_app.response_class(
        buf.getvalue(),
        mimetype='application/zip',
        headers={'Content-Disposition': 'attachment; filename=resetapp_export.zip'}
    )


@bp.route('/audit/retention', methods=['POST'])
@login_required
@admin_required
def set_audit_retention():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    days_raw = request.form.get('retention_days', '').strip()
    try:
        days = int(days_raw)
    except ValueError:
        flash('Retention days must be a number.', 'danger')
        return redirect(url_for('admin.admin_audit'))
    if days < 1 or days > 3650:
        flash('Retention days must be between 1 and 3650.', 'danger')
        return redirect(url_for('admin.admin_audit'))
    cutoff = datetime.now() - timedelta(days=days)
    remaining = prune_audit_logs(cutoff)
    flash(f'Applied retention: kept {remaining} audit entries.', 'success')
    log_audit_event(
        admin_email=session['user_info']['email'],
        outcome='Audit Retention Applied',
        detail=f'{days} days',
        role=session.get('role'),
        action_type='admin_action',
        admin_ou=session.get('orgUnitPath'),
        admin_school=session.get('school')
    )
    return redirect(url_for('admin.admin_audit'))


@bp.route('/bug_reports/close', methods=['POST'])
@login_required
@admin_required
def close_bug_report():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    report_id = request.form.get('id')
    updated = update_bug_report(report_id, {'status': 'Closed'})
    if updated:
        flash(f'Closed report {report_id}', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Bug Report Closed',
            detail=updated.get('title', report_id),
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    else:
        flash(f'Report {report_id} not found.', 'danger')
    return redirect(url_for('admin.admin_bugs'))


@bp.route('/bug_reports/update', methods=['POST'])
@login_required
@admin_required
def update_bug_report_route():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    report_id = request.form.get('id')
    status = request.form.get('status', '').strip()
    notes = request.form.get('notes', '').strip()
    updates = {}
    if status:
        updates['status'] = status
    if notes:
        updates['notes'] = notes
    if not updates:
        flash('No changes submitted.', 'warning')
        return redirect(url_for('admin.admin_bugs'))

    updated = update_bug_report(report_id, updates)
    if updated:
        flash(f'Updated report {report_id}', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Bug Report Updated',
            detail=updated.get('title', report_id),
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    else:
        flash(f'Report {report_id} not found.', 'danger')
    return redirect(url_for('admin.admin_bugs'))


@bp.route('/known_issues/add', methods=['POST'])
@login_required
@admin_required
def add_known_issue():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    issue_text = request.form.get('issue', '').strip()
    update_note = request.form.get('update_note', '').strip()
    level = request.form.get('level', 'support').strip().lower()
    if level not in ('global', 'support'):
        level = 'support'
    if not issue_text:
        flash('Known issue text is required.', 'danger')
        return redirect(url_for('admin.admin_known_issues'))
    issue = {
        'id': secrets.token_hex(4),
        'text': issue_text,
        'status': 'Active',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'level': level,
        'update_note': update_note,
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S') if update_note else ''
    }
    add_known_issue_record(issue)
    flash('Known issue added.', 'success')
    log_audit_event(
        admin_email=session['user_info']['email'],
        outcome='Known Issue Added',
        detail=issue_text,
        role=session.get('role'),
        action_type='admin_action',
        admin_ou=session.get('orgUnitPath'),
        admin_school=session.get('school')
    )
    return redirect(url_for('admin.admin_known_issues'))


@bp.route('/known_issues/update', methods=['POST'])
@login_required
@admin_required
def update_known_issue_route():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    issue_id = request.form.get('id')
    issue_text = request.form.get('issue', '').strip()
    update_note = request.form.get('update_note', '').strip()
    level = request.form.get('level', '').strip().lower()
    updates = {}
    if issue_text:
        updates['text'] = issue_text
    if update_note:
        updates['update_note'] = update_note
        updates['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    elif 'update_note' in request.form:
        updates['update_note'] = ''
        updates['updated_at'] = ''
    if level in ('global', 'support'):
        updates['level'] = level
    if not updates:
        flash('No changes submitted.', 'warning')
        return redirect(url_for('admin.admin_known_issues'))
    updated = update_known_issue(issue_id, updates)
    if updated:
        flash('Known issue updated.', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Known Issue Updated',
            detail=updated.get('text', issue_id),
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    else:
        flash('Known issue not found.', 'danger')
    return redirect(url_for('admin.admin_known_issues'))


@bp.route('/known_issues/delete', methods=['POST'])
@login_required
@admin_required
def delete_known_issue_route():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    issue_id = request.form.get('id')
    deleted = delete_known_issue(issue_id)
    if deleted:
        flash('Known issue deleted.', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Known Issue Deleted',
            detail=deleted.get('text', issue_id),
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    else:
        flash('Known issue not found.', 'danger')
    return redirect(url_for('admin.admin_known_issues'))


@bp.route('/known_issues/resolve', methods=['POST'])
@login_required
@admin_required
def resolve_known_issue():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    issue_id = request.form.get('id')
    updated = update_known_issue(issue_id, {
        'status': 'Resolved',
        'resolved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    if updated:
        flash('Known issue resolved.', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Known Issue Resolved',
            detail=updated.get('text', issue_id),
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    else:
        flash('Known issue not found.', 'danger')
    return redirect(url_for('admin.admin_known_issues'))


@bp.route('/add_admin', methods=['POST'])
@login_required
@admin_required
def add_admin():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    email = request.form['email'].strip().lower()
    admins = load_admins()
    if email in admins:
        flash(f'{email} already an admin.', 'warning')
    else:
        admins.append(email)
        save_admins(admins)
        flash(f'Added {email}', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Admin Added',
            detail=email,
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    return redirect(url_for('admin.admin_admins'))


@bp.route('/add_global_admin', methods=['POST'])
@login_required
@role_required({ROLE_GLOBAL_ADMIN})
def add_global_admin():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    email = request.form.get('email', '').strip().lower()
    if not email:
        flash('Email is required.', 'warning')
        return redirect(url_for('admin.admin_admins'))
    admins = load_global_admins()
    if email in admins:
        flash(f'{email} already a global admin.', 'warning')
    else:
        admins.append(email)
        save_global_admins(admins)
        flash(f'Added {email} as global admin.', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Global Admin Added',
            detail=email,
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    return redirect(url_for('admin.admin_admins'))


@bp.route('/remove_admin', methods=['POST'])
@login_required
@admin_required
def remove_admin():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    email = request.form['email'].strip().lower()
    admins = load_admins()
    if email not in admins:
        flash(f'{email} not found.', 'warning')
    elif email == session['user_info']['email'].lower():
        flash('Cannot remove yourself.', 'danger')
    else:
        admins.remove(email)
        save_admins(admins)
        flash(f'Removed {email}', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Admin Removed',
            detail=email,
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    return redirect(url_for('admin.admin_admins'))


@bp.route('/remove_global_admin', methods=['POST'])
@login_required
@role_required({ROLE_GLOBAL_ADMIN})
def remove_global_admin():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    email = request.form.get('email', '').strip().lower()
    admins = load_global_admins()
    if email not in admins:
        flash(f'{email} not found.', 'warning')
    elif email == session['user_info']['email'].lower():
        flash('Cannot remove yourself.', 'danger')
    else:
        admins.remove(email)
        save_global_admins(admins)
        flash(f'Removed {email}', 'success')
        log_audit_event(
            admin_email=session['user_info']['email'],
            outcome='Global Admin Removed',
            detail=email,
            role=session.get('role'),
            action_type='admin_action',
            admin_ou=session.get('orgUnitPath'),
            admin_school=session.get('school')
        )
    return redirect(url_for('admin.admin_admins'))


@bp.route('/approve_request', methods=['POST'])
@login_required
@admin_required
def approve_request():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    rid = request.form['id']
    reqs = load_requests()
    for req in reqs:
        if req['id'] == rid:
            req['status'] = 'Approved'
            flash(f'Approved {rid}', 'success')
            log_audit_event(
                admin_email=session['user_info']['email'],
                outcome='Reset Request Approved',
                detail=f"{req['email']} ({rid})",
                role=session.get('role'),
                action_type='admin_action',
                admin_ou=session.get('orgUnitPath'),
                admin_school=session.get('school')
            )
            break
    save_requests(reqs)
    return redirect(url_for('admin.admin_requests'))


@bp.route('/deny_request', methods=['POST'])
@login_required
@admin_required
def deny_request():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)
    rid = request.form['id']
    reqs = load_requests()
    for req in reqs:
        if req['id'] == rid:
            req['status'] = 'Denied'
            flash(f'Denied {rid}', 'info')
            log_audit_event(
                admin_email=session['user_info']['email'],
                outcome='Reset Request Denied',
                detail=f"{req['email']} ({rid})",
                role=session.get('role'),
                action_type='admin_action',
                admin_ou=session.get('orgUnitPath'),
                admin_school=session.get('school')
            )
            break
    save_requests(reqs)
    return redirect(url_for('admin.admin_requests'))


@bp.route('/search_staff')
@login_required
@admin_required
def search_staff_route():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])

    staff_prefixes = current_app.config.get('STAFF_OU_PREFIXES', [])
    try:
        staff = search_staff(q, staff_prefixes)
    except HttpError:
        return jsonify([]), 500

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
        staff = [u for u in staff if match(u)]

    return jsonify([
        {
            'label': f"{u['name'].get('givenName', '')} {u['name'].get('familyName', '')} - {u['primaryEmail']}",
            'value': u['primaryEmail']
        } for u in staff
    ])
