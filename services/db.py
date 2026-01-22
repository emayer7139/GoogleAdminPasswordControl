import json
import os

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


def init_db(app):
    engine = create_engine(app.config['DATABASE_URL'], future=True)
    app.extensions['db_engine'] = engine
    metadata.create_all(engine)
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

    with engine.begin() as conn:
        if conn.execute(select(audit_logs_table.c.id)).first() is None:
            if os.path.exists(audit_path):
                with open(audit_path, 'r') as f:
                    for entry in json.load(f):
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
            if os.path.exists(bug_path):
                with open(bug_path, 'r') as f:
                    for entry in json.load(f):
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
            if os.path.exists(known_path):
                with open(known_path, 'r') as f:
                    for entry in json.load(f):
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
            if os.path.exists(login_path):
                with open(login_path, 'r') as f:
                    for entry in json.load(f):
                        conn.execute(login_logs_table.insert().values(
                            timestamp=entry.get('timestamp', ''),
                            user=entry.get('user', ''),
                            outcome=entry.get('outcome', ''),
                            ip=entry.get('ip', '')
                        ))
