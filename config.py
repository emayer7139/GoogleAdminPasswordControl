import os
from dotenv import load_dotenv

# Load environment variables from .env in project root
BASEDIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASEDIR, '.env'))

class Config:
    # Flask
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'development_secret_key')

    # OAuth2 SSO
    GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID',     'your_google_client_id')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', 'your_google_client_secret')

    # App URLs
    BASE_URL     = os.environ.get('BASE_URL',     'http://localhost:5000')
    REDIRECT_URI = os.environ.get('REDIRECT_URI', BASE_URL + '/oauth2callback')

    # Service account JSON key for Admin SDK
    #  - Either set SERVICE_ACCOUNT_FILE in your .env
    #  - Or drop a UTF‑8 JSON key at credentials/sa-key.json
    SERVICE_ACCOUNT_FILE = os.environ.get(
        'SERVICE_ACCOUNT_FILE',
        os.path.join(BASEDIR, 'credentials', 'student-password-manager-38ef54f19ebb.json')
    )

    # Super‑admin for domain‑wide delegation
    ADMIN_USER = os.environ.get('ADMIN_USER', 'evan.ayers@hart.k12.ga.us')
