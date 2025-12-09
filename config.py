import os
from dotenv import load_dotenv

# Load environment variables from .env in project root
BASEDIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASEDIR, '.env'))

class Config:
    # Flask
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)

    # OAuth2 SSO
    GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID',     'your_google_client_id')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', 'your_google_client_secret')
    # Base URL setting
    BASE_URL = os.environ.get("BASE_URL")
    # Redirect URI: either explicitly set or constructed from BASE_URL
    REDIRECT_URI = os.environ.get("REDIRECT_URI", BASE_URL + "/oauth2callback")
    # App URLs
    BASE_URL     = os.environ.get('BASE_URL')
    REDIRECT_URI = os.environ.get('REDIRECT_URI', BASE_URL + '/oauth2callback')

    # Service account JSON key for Admin SDK
    SERVICE_ACCOUNT_FILE = os.environ.get('SERVICE_ACCOUNT_FILE')

    # Super‑admin for domain‑wide delegation
    ADMIN_USER = os.environ.get('ADMIN_USER', 'username@example.com')


    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
