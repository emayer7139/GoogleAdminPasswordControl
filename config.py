import os
from dotenv import load_dotenv

# ─── load from .env ─────────────────────────────────────────────────────
BASEDIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASEDIR, '.env'))

class Config:
    # ─── Flask secret ────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get(
        'FLASK_SECRET_KEY',
        'development_secret_key'
    )

    # ─── OAuth2 SSO ─────────────────────────────────────────────────────
    GOOGLE_CLIENT_ID     = os.environ['GOOGLE_CLIENT_ID']
    GOOGLE_CLIENT_SECRET = os.environ['GOOGLE_CLIENT_SECRET']

    # ─── App host/base ──────────────────────────────────────────────────
    BASE_URL = os.environ.get('BASE_URL', 'http://127.0.0.1:5000')
    # build redirect if none is set explicitly
    REDIRECT_URI = os.environ.get(
        'REDIRECT_URI',
        f"{BASE_URL}/oauth2callback"
    )

    # ─── Service account (must be JSON) ────────────────────────────────
    SERVICE_ACCOUNT_FILE = os.environ['SERVICE_ACCOUNT_FILE']

    # ─── Super-admin for Admin SDK delegation ───────────────────────────
    ADMIN_USER = os.environ.get(
        'ADMIN_USER',
        'evan.ayers@hart.k12.ga.us'
    )

    # ─── (Optional) scopes if you need them elsewhere ──────────────────
    OAUTH2_SCOPES = [
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
    ]
  # ─── Developer mode toggle ─────────────────────────────────
    DEV_MODE = os.getenv("DEV_MODE", "false").lower() in ("true", "1", "t")