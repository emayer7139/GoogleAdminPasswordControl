import json
import os
from datetime import datetime

from flask import current_app
from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    Column,
    Integer,
    String,
    Text,
    select
)

metadata = MetaData()

DEFAULT_APP_SETTINGS = {
    'require_reset_request': 'true',
    'reset_cooldown_minutes': '0',
    'require_teacher_approval': 'false',
}

schema_meta_table = Table(
    'schema_meta',
    metadata,
    Column('key', String(64), primary_key=True),
    Column('value', String(64), nullable=False),
)

audit_logs_table = Table(
    'audit_logs',
    metadata,
    Column('id', Integer, primary_key=True),
    Column('timestamp', String(19), nullable=False),
    Column('admin', String(255), nullable=False),
    Column('student', String(255), nullable=True),
    Column('outcome', String(255), nullable=True),
    Column('role', String(64), nullable=True),
    Column('action_type', String(64), nullable=True),
    Column('admin_ou', String(255), nullable=True),
    Column('admin_school', String(255), nullable=True),
)

bug_reports_table = Table(
    'bug_reports',
    metadata,
    Column('id', String(32), primary_key=True),
    Column('timestamp', String(19), nullable=False),
    Column('reporter', String(255), nullable=False),
    Column('title', String(255), nullable=False),
    Column('description', Text, nullable=False),
    Column('severity', String(32), nullable=True),
    Column('page', String(255), nullable=True),
    Column('status', String(32), nullable=True),
    Column('attachment', String(255), nullable=True),
    Column('notes', Text, nullable=True),
)

known_issues_table = Table(
    'known_issues',
    metadata,
    Column('id', String(32), primary_key=True),
    Column('text', Text, nullable=False),
    Column('status', String(32), nullable=False),
    Column('created_at', String(19), nullable=False),
    Column('resolved_at', String(19), nullable=True),
    Column('level', String(32), nullable=True),
    Column('update_note', Text, nullable=True),
    Column('updated_at', String(19), nullable=True),
)

login_logs_table = Table(
    'login_logs',
    metadata,
    Column('id', Integer, primary_key=True),
    Column('timestamp', String(19), nullable=False),
    Column('user', String(255), nullable=False),
    Column('outcome', String(255), nullable=False),
    Column('ip', String(64), nullable=True),
)

admin_users_table = Table(
    'admin_users',
    metadata,
    Column('email', String(255), primary_key=True),
)

global_admins_table = Table(
    'global_admins',
    metadata,
    Column('email', String(255), primary_key=True),
)

reset_requests_table = Table(
    'reset_requests',
    metadata,
    Column('id', String(32), primary_key=True),
    Column('email', String(255), nullable=False),
    Column('date', String(10), nullable=False),
    Column('status', String(32), nullable=False),
)

app_settings_table = Table(
    'app_settings',
    metadata,
    Column('key', String(64), primary_key=True),
    Column('value', String(255), nullable=False),
)

theme_preferences_table = Table(
    'theme_preferences',
    metadata,
    Column('email', String(255), primary_key=True),
    Column('theme', String(16), nullable=False),
)

classroom_sync_table = Table(
    'classroom_sync',
    metadata,
    Column('email', String(255), primary_key=True),
    Column('count', Integer, nullable=False),
    Column('timestamp', String(19), nullable=True),
)


def init_db(app):
    engine = create_engine(app.config['DATABASE_URL'], future=True)
    app.extensions['db_engine'] = engine
    metadata.create_all(engine)
    _ensure_schema_meta(engine)
    _ensure_app_settings(engine)
    _migrate_json(engine, app.root_path)


def get_engine():
    engine = current_app.extensions.get('db_engine')
    if engine is None:
        engine = create_engine(current_app.config['DATABASE_URL'], future=True)
        current_app.extensions['db_engine'] = engine
    return engine


def _migrate_json(engine, root_path):
    audit_path = os.path.join(root_path, 'audit_logs.json')
    bug_path = os.path.join(root_path, 'bug_reports.json')
    known_path = os.path.join(root_path, 'known_issues.json')
    login_path = os.path.join(root_path, 'login_logs.json')
    admin_path = os.path.join(root_path, 'admin_users.json')
    global_path = os.path.join(root_path, 'global_admins.json')
    requests_path = os.path.join(root_path, 'reset_requests.json')
    theme_path = os.path.join(root_path, 'theme_preferences.json')
    classroom_path = os.path.join(root_path, 'classroom_sync.json')

    def load_json(path, default):
        if not os.path.exists(path):
            return default
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return default

    with engine.begin() as conn:
        if conn.execute(select(audit_logs_table.c.id)).first() is None:
            for entry in load_json(audit_path, []):
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

        if conn.execute(select(bug_reports_table.c.id)).first() is None:
            for entry in load_json(bug_path, []):
                conn.execute(bug_reports_table.insert().values(
                    id=entry.get('id', ''),
                    timestamp=entry.get('timestamp', ''),
                    reporter=entry.get('reporter', ''),
                    title=entry.get('title', ''),
                    description=entry.get('description', ''),
                    severity=entry.get('severity', ''),
                    page=entry.get('page', ''),
                    status=entry.get('status', ''),
                    attachment=entry.get('attachment', ''),
                    notes=entry.get('notes', '')
                ))

        if conn.execute(select(known_issues_table.c.id)).first() is None:
            for entry in load_json(known_path, []):
                conn.execute(known_issues_table.insert().values(
                    id=entry.get('id', ''),
                    text=entry.get('text', ''),
                    status=entry.get('status', ''),
                    created_at=entry.get('created_at', ''),
                    resolved_at=entry.get('resolved_at', ''),
                    level=entry.get('level', 'support'),
                    update_note=entry.get('update_note', ''),
                    updated_at=entry.get('updated_at', '')
                ))

        if conn.execute(select(login_logs_table.c.id)).first() is None:
            for entry in load_json(login_path, []):
                conn.execute(login_logs_table.insert().values(
                    timestamp=entry.get('timestamp', ''),
                    user=entry.get('user', ''),
                    outcome=entry.get('outcome', ''),
                    ip=entry.get('ip', '')
                ))

        if conn.execute(select(admin_users_table.c.email)).first() is None:
            seen = set()
            for email in load_json(admin_path, []):
                addr = str(email).strip().lower()
                if addr and addr not in seen:
                    seen.add(addr)
                    conn.execute(admin_users_table.insert().values(email=addr))

        if conn.execute(select(global_admins_table.c.email)).first() is None:
            seen = set()
            for email in load_json(global_path, []):
                addr = str(email).strip().lower()
                if addr and addr not in seen:
                    seen.add(addr)
                    conn.execute(global_admins_table.insert().values(email=addr))

        if conn.execute(select(reset_requests_table.c.id)).first() is None:
            seen = set()
            for entry in load_json(requests_path, []):
                rid = str(entry.get('id', '')).strip()
                email = str(entry.get('email', '')).strip().lower()
                if not rid or rid in seen:
                    continue
                seen.add(rid)
                conn.execute(reset_requests_table.insert().values(
                    id=rid,
                    email=email,
                    date=entry.get('date', ''),
                    status=entry.get('status', 'Pending')
                ))

        if conn.execute(select(theme_preferences_table.c.email)).first() is None:
            prefs = load_json(theme_path, {})
            if isinstance(prefs, dict):
                for email, theme in prefs.items():
                    addr = str(email).strip().lower()
                    value = str(theme).strip()
                    if addr and value:
                        conn.execute(theme_preferences_table.insert().values(
                            email=addr,
                            theme=value
                        ))

        if conn.execute(select(classroom_sync_table.c.email)).first() is None:
            sync_data = load_json(classroom_path, {})
            if isinstance(sync_data, dict):
                for email, payload in sync_data.items():
                    addr = str(email).strip().lower()
                    if not addr:
                        continue
                    count = payload.get('count', 0) if isinstance(payload, dict) else 0
                    timestamp = payload.get('timestamp', '') if isinstance(payload, dict) else ''
                    try:
                        count = int(count)
                    except (TypeError, ValueError):
                        count = 0
                    conn.execute(classroom_sync_table.insert().values(
                        email=addr,
                        count=count,
                        timestamp=timestamp
                    ))


def _ensure_schema_meta(engine):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with engine.begin() as conn:
        existing = conn.execute(
            select(schema_meta_table.c.value)
            .where(schema_meta_table.c.key == 'initialized_at')
        ).scalar()
        if not existing:
            conn.execute(schema_meta_table.insert().values(
                key='initialized_at',
                value=now
            ))


def _ensure_app_settings(engine):
    with engine.begin() as conn:
        existing = set(conn.execute(select(app_settings_table.c.key)).scalars().all())
        for key, value in DEFAULT_APP_SETTINGS.items():
            if key not in existing:
                conn.execute(app_settings_table.insert().values(
                    key=key,
                    value=value
                ))
