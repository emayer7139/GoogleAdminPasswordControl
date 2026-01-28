from datetime import datetime

from sqlalchemy import delete, select

from services.db import (
    get_engine,
    audit_logs_table,
    bug_reports_table,
    known_issues_table,
    login_logs_table,
    admin_users_table,
    global_admins_table,
    reset_requests_table,
    app_settings_table,
    DEFAULT_APP_SETTINGS,
    theme_preferences_table,
    classroom_sync_table,
)


def load_admins():
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(admin_users_table.c.email).order_by(admin_users_table.c.email)
        ).scalars().all()
    return list(rows)


def save_admins(admins):
    unique = sorted({email.strip().lower() for email in admins if email})
    with get_engine().begin() as conn:
        conn.execute(delete(admin_users_table))
        if unique:
            conn.execute(
                admin_users_table.insert(),
                [{'email': email} for email in unique]
            )


def load_global_admins():
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(global_admins_table.c.email).order_by(global_admins_table.c.email)
        ).scalars().all()
    return list(rows)


def save_global_admins(admins):
    unique = sorted({email.strip().lower() for email in admins if email})
    with get_engine().begin() as conn:
        conn.execute(delete(global_admins_table))
        if unique:
            conn.execute(
                global_admins_table.insert(),
                [{'email': email} for email in unique]
            )


def load_requests():
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(reset_requests_table)
            .order_by(reset_requests_table.c.date, reset_requests_table.c.id)
        ).mappings().all()
    return [dict(row) for row in rows]


def load_app_settings():
    settings = dict(DEFAULT_APP_SETTINGS)
    with get_engine().connect() as conn:
        rows = conn.execute(select(app_settings_table)).mappings().all()
    for row in rows:
        key = row.get('key')
        value = row.get('value')
        if key:
            settings[key] = value
    return settings


def set_app_settings(settings):
    with get_engine().begin() as conn:
        for key, value in settings.items():
            key = str(key).strip()
            if not key:
                continue
            val = '' if value is None else str(value).strip()
            result = conn.execute(
                app_settings_table.update()
                .where(app_settings_table.c.key == key)
                .values(value=val)
            )
            if result.rowcount == 0:
                conn.execute(app_settings_table.insert().values(
                    key=key,
                    value=val
                ))


def save_requests(reqs):
    rows = []
    seen = set()
    for req in reqs:
        rid = str(req.get('id', '')).strip()
        if not rid or rid in seen:
            continue
        seen.add(rid)
        rows.append({
            'id': rid,
            'email': (req.get('email', '') or '').strip().lower(),
            'date': req.get('date', ''),
            'status': req.get('status', 'Pending')
        })
    with get_engine().begin() as conn:
        conn.execute(delete(reset_requests_table))
        if rows:
            conn.execute(reset_requests_table.insert(), rows)


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


def get_theme_for_user(email):
    if not email:
        return None
    addr = email.lower()
    with get_engine().connect() as conn:
        row = conn.execute(
            select(theme_preferences_table.c.theme)
            .where(theme_preferences_table.c.email == addr)
        ).scalar()
    return row


def set_theme_for_user(email, theme):
    if not email:
        return
    addr = email.lower()
    with get_engine().begin() as conn:
        result = conn.execute(
            theme_preferences_table.update()
            .where(theme_preferences_table.c.email == addr)
            .values(theme=theme)
        )
        if result.rowcount == 0:
            conn.execute(theme_preferences_table.insert().values(email=addr, theme=theme))


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
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(classroom_sync_table)
        ).mappings().all()
    return {
        row['email']: {
            'count': row.get('count', 0),
            'timestamp': row.get('timestamp', '')
        }
        for row in rows
    }


def get_classroom_sync(email):
    if not email:
        return None
    addr = email.lower()
    with get_engine().connect() as conn:
        row = conn.execute(
            select(classroom_sync_table.c.count, classroom_sync_table.c.timestamp)
            .where(classroom_sync_table.c.email == addr)
        ).first()
    if not row:
        return None
    return {'count': row[0], 'timestamp': row[1]}


def set_classroom_sync(email, count):
    if not email:
        return
    addr = email.lower()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_engine().begin() as conn:
        result = conn.execute(
            classroom_sync_table.update()
            .where(classroom_sync_table.c.email == addr)
            .values(count=int(count), timestamp=timestamp)
        )
        if result.rowcount == 0:
            conn.execute(classroom_sync_table.insert().values(
                email=addr,
                count=int(count),
                timestamp=timestamp
            ))


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
