import json
import os
from datetime import datetime

from flask import current_app
from sqlalchemy import select, delete

from services.db import (
    get_engine,
    audit_logs_table,
    bug_reports_table,
    known_issues_table,
    login_logs_table
)

ADMIN_FILE = 'admin_users.json'
GLOBAL_ADMIN_FILE = 'global_admins.json'
REQUESTS_FILE = 'reset_requests.json'
AUDIT_LOG_FILE = 'audit_logs.json'
LOGIN_LOG_FILE = 'login_logs.json'
THEME_FILE = 'theme_preferences.json'
BUG_REPORTS_FILE = 'bug_reports.json'
CLASSROOM_SYNC_FILE = 'classroom_sync.json'
KNOWN_ISSUES_FILE = 'known_issues.json'



def _data_path(filename):
    return os.path.join(current_app.root_path, filename)


def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, 'r') as f:
        return json.load(f)


def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def load_admins():
    return load_json(_data_path(ADMIN_FILE))


def save_admins(admins):
    save_json(_data_path(ADMIN_FILE), admins)


def load_global_admins():
    return load_json(_data_path(GLOBAL_ADMIN_FILE))


def save_global_admins(admins):
    save_json(_data_path(GLOBAL_ADMIN_FILE), admins)


def load_requests():
    return load_json(_data_path(REQUESTS_FILE))


def save_requests(reqs):
    save_json(_data_path(REQUESTS_FILE), reqs)


def append_audit_log(entry):
    with get_engine().begin() as conn:
        conn.execute(audit_logs_table.insert().values(
            timestamp=entry.get('timestamp', ''),
            admin=entry.get('admin', ''),
            student=entry.get('student', ''),
            outcome=entry.get('outcome', ''),
            role=entry.get('role', ''),
            action_type=entry.get('action_type', ''),
            admin_ou=entry.get('admin_ou', ''),
            admin_school=entry.get('admin_school', '')
        ))


def append_login_log(entry):
    with get_engine().begin() as conn:
        conn.execute(login_logs_table.insert().values(
            timestamp=entry.get('timestamp', ''),
            user=entry.get('user', ''),
            outcome=entry.get('outcome', ''),
            ip=entry.get('ip', '')
        ))


def get_audit_logs():
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(audit_logs_table)
            .order_by(audit_logs_table.c.timestamp.desc(), audit_logs_table.c.id.desc())
        ).mappings().all()
    return [dict(row) for row in rows]


def get_login_logs():
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(login_logs_table)
            .order_by(login_logs_table.c.timestamp.desc(), login_logs_table.c.id.desc())
        ).mappings().all()
    return [dict(row) for row in rows]


def persist_audit_logs():
    return


def prune_audit_logs(cutoff_dt):
    cutoff = cutoff_dt.strftime('%Y-%m-%d %H:%M:%S')
    with get_engine().begin() as conn:
        conn.execute(delete(audit_logs_table).where(audit_logs_table.c.timestamp < cutoff))
        remaining = conn.execute(select(audit_logs_table.c.id)).all()
    return len(remaining)


def log_audit_event(admin_email, outcome, detail, role=None, action_type=None, admin_ou=None, admin_school=None):
    append_audit_log({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'admin': admin_email,
        'student': detail,
        'outcome': outcome,
        'role': role,
        'action_type': action_type,
        'admin_ou': admin_ou,
        'admin_school': admin_school
    })


def log_failed_login(email, reason, ip=None):
    append_login_log({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': email,
        'outcome': f'Failed: {reason}',
        'ip': ip or ''
    })


def load_theme_preferences():
    path = _data_path(THEME_FILE)
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def save_theme_preferences(prefs):
    save_json(_data_path(THEME_FILE), prefs)


def get_theme_for_user(email):
    prefs = load_theme_preferences()
    return prefs.get(email.lower())


def set_theme_for_user(email, theme):
    prefs = load_theme_preferences()
    prefs[email.lower()] = theme
    save_theme_preferences(prefs)


def load_bug_reports():
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(bug_reports_table)
            .order_by(bug_reports_table.c.timestamp.desc())
        ).mappings().all()
    return [dict(row) for row in rows]


def save_bug_reports(reports):
    with get_engine().begin() as conn:
        conn.execute(delete(bug_reports_table))
        for report in reports:
            conn.execute(bug_reports_table.insert().values(
                id=report.get('id', ''),
                timestamp=report.get('timestamp', ''),
                reporter=report.get('reporter', ''),
                title=report.get('title', ''),
                description=report.get('description', ''),
                severity=report.get('severity', ''),
                page=report.get('page', ''),
                status=report.get('status', ''),
                attachment=report.get('attachment', ''),
                notes=report.get('notes', '')
            ))


def add_bug_report(report):
    with get_engine().begin() as conn:
        conn.execute(bug_reports_table.insert().values(
            id=report.get('id', ''),
            timestamp=report.get('timestamp', ''),
            reporter=report.get('reporter', ''),
            title=report.get('title', ''),
            description=report.get('description', ''),
            severity=report.get('severity', ''),
            page=report.get('page', ''),
            status=report.get('status', ''),
            attachment=report.get('attachment', ''),
            notes=report.get('notes', '')
        ))


def update_bug_report(report_id, updates):
    with get_engine().begin() as conn:
        row = conn.execute(
            select(bug_reports_table).where(bug_reports_table.c.id == report_id)
        ).mappings().first()
        if not row:
            return None
        conn.execute(
            bug_reports_table.update()
            .where(bug_reports_table.c.id == report_id)
            .values(**updates)
        )
    updated = dict(row)
    updated.update(updates)
    return updated


def load_classroom_sync():
    path = _data_path(CLASSROOM_SYNC_FILE)
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def save_classroom_sync(sync_data):
    save_json(_data_path(CLASSROOM_SYNC_FILE), sync_data)


def get_classroom_sync(email):
    sync_data = load_classroom_sync()
    return sync_data.get(email.lower())


def set_classroom_sync(email, count):
    sync_data = load_classroom_sync()
    sync_data[email.lower()] = {
        'count': count,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    save_classroom_sync(sync_data)


def load_known_issues():
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(known_issues_table)
            .order_by(known_issues_table.c.created_at.desc())
        ).mappings().all()
    issues = [dict(row) for row in rows]
    for issue in issues:
        issue['level'] = issue.get('level') or 'support'
        issue['update_note'] = issue.get('update_note') or ''
        issue['updated_at'] = issue.get('updated_at') or ''
    return issues


def save_known_issues(issues):
    with get_engine().begin() as conn:
        conn.execute(delete(known_issues_table))
        for issue in issues:
            conn.execute(known_issues_table.insert().values(
                id=issue.get('id', ''),
                text=issue.get('text', ''),
                status=issue.get('status', ''),
                created_at=issue.get('created_at', ''),
                resolved_at=issue.get('resolved_at', ''),
                level=issue.get('level', 'support'),
                update_note=issue.get('update_note', ''),
                updated_at=issue.get('updated_at', '')
            ))


def add_known_issue(issue):
    with get_engine().begin() as conn:
        conn.execute(known_issues_table.insert().values(
            id=issue.get('id', ''),
            text=issue.get('text', ''),
            status=issue.get('status', ''),
            created_at=issue.get('created_at', ''),
            resolved_at=issue.get('resolved_at', ''),
            level=issue.get('level', 'support'),
            update_note=issue.get('update_note', ''),
            updated_at=issue.get('updated_at', '')
        ))


def update_known_issue(issue_id, updates):
    with get_engine().begin() as conn:
        row = conn.execute(
            select(known_issues_table).where(known_issues_table.c.id == issue_id)
        ).mappings().first()
        if not row:
            return None
        conn.execute(
            known_issues_table.update()
            .where(known_issues_table.c.id == issue_id)
            .values(**updates)
        )
    updated = dict(row)
    updated.update(updates)
    return updated


def delete_known_issue(issue_id):
    with get_engine().begin() as conn:
        row = conn.execute(
            select(known_issues_table).where(known_issues_table.c.id == issue_id)
        ).mappings().first()
        if not row:
            return None
        conn.execute(
            delete(known_issues_table).where(known_issues_table.c.id == issue_id)
        )
    return dict(row)
