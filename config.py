import os
import secrets
from dotenv import load_dotenv

BASEDIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASEDIR, '.env'), override=True)


def _split_csv(value):
    return [item.strip() for item in value.split(',') if item.strip()]


def _env_truthy(name, default='false'):
    value = os.environ.get(name, default)
    return value.strip().lower() in ('1', 'true', 'yes', 'y', 'on')


class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)

    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'your_google_client_id')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', 'your_google_client_secret')

    BASE_URL = os.environ.get('BASE_URL')
    REDIRECT_URI = os.environ.get('REDIRECT_URI') or (f"{BASE_URL}/oauth2callback" if BASE_URL else '')

    SERVICE_ACCOUNT_FILE = os.environ.get('SERVICE_ACCOUNT_FILE')
    ADMIN_USER = os.environ.get('ADMIN_USER', 'username@example.com')

    RESET_LIMIT = int(os.environ.get('RESET_LIMIT', '5'))

    GLOBAL_ADMIN_EMAILS = set(_split_csv(os.environ.get('GLOBAL_ADMIN_EMAILS', '')))

    ROLE_OU_PREFIXES = {
        'teacher': _split_csv(os.environ.get('ROLE_OU_TEACHER_PREFIXES', '/Staff/Teachers,/Staff/Faculty')),
        'media_specialist': _split_csv(
            os.environ.get('ROLE_OU_MEDIA_PREFIXES', '/Staff/Media Specialists,/Staff/Media')
        )
    }

    STAFF_OU_PREFIXES = _split_csv(
        os.environ.get(
            'STAFF_OU_PREFIXES',
            '/Staff/District,/Staff/Faculty,/Staff/Long Term Subs,/Staff/School Admins,/Staff/Media Specialists'
        )
    )
    STAFF_EMAIL_DOMAINS = _split_csv(os.environ.get('STAFF_EMAIL_DOMAINS', ''))

    STUDENT_OU_PREFIXES = _split_csv(os.environ.get('STUDENT_OU_PREFIXES', '/Students'))
    STUDENT_EMAIL_DOMAINS = _split_csv(os.environ.get('STUDENT_EMAIL_DOMAINS', ''))

    SCHOOL_OU_SKIP_SEGMENTS = set(
        seg.lower() for seg in _split_csv(
            os.environ.get(
                'SCHOOL_OU_SKIP_SEGMENTS',
                'Teachers,Faculty,School Admins,Media Specialists,District,Long Term Subs'
            )
        )
    )

    USE_ADHOC_SSL = _env_truthy('USE_ADHOC_SSL', 'true')
    SESSION_COOKIE_SECURE = _env_truthy('SESSION_COOKIE_SECURE', 'true' if USE_ADHOC_SSL else 'false')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    DEV_LOGIN_ENABLED = _env_truthy('DEV_LOGIN_ENABLED', 'false')
    DEV_LOGIN_EMAIL = os.environ.get('DEV_LOGIN_EMAIL', 'dev@example.com').lower()
    DEV_LOGIN_ROLE = os.environ.get('DEV_LOGIN_ROLE', 'global_admin')
    DEV_TEACHER_EMAIL = os.environ.get('DEV_TEACHER_EMAIL', 'teacher.dev@example.com').lower()
    DEV_MEDIA_EMAIL = os.environ.get('DEV_MEDIA_EMAIL', 'media.dev@example.com').lower()

    UPLOAD_FOLDER = os.path.join(BASEDIR, 'static', 'uploads', 'bug_reports')
    ALLOWED_BUG_UPLOADS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    DATABASE_URL = os.environ.get(
        'DATABASE_URL',
        f"sqlite:///{os.path.join(BASEDIR, 'data', 'resetapp.db')}"
    )

    SMTP_HOST = os.environ.get('SMTP_HOST', '')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USER = os.environ.get('SMTP_USER', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    SMTP_FROM = os.environ.get('SMTP_FROM', '')
    SMTP_USE_TLS = _env_truthy('SMTP_USE_TLS', 'true')

    STATUS_EMAIL_ENABLED = _env_truthy('STATUS_EMAIL_ENABLED', 'false')
    STATUS_EMAIL_RECIPIENTS = _split_csv(os.environ.get('STATUS_EMAIL_RECIPIENTS', ''))
    STATUS_EMAIL_COOLDOWN_MINUTES = int(os.environ.get('STATUS_EMAIL_COOLDOWN_MINUTES', '30'))
    STATUS_EMAIL_NOTIFY_ON_RECOVERY = _env_truthy('STATUS_EMAIL_NOTIFY_ON_RECOVERY', 'true')
    STATUS_EMAIL_TOKEN = os.environ.get('STATUS_EMAIL_TOKEN', '')
