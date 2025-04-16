import os
from dotenv import load_dotenv

# Automatically load variables from the .env file
load_dotenv()

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "development_secret_key")

    # Google OAuth credentials for user SSO
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "your_google_client_id")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "your_google_client_secret")

    # Base URL setting - either your domain or localhost for testing
    BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
    
    # Redirect URI: either explicitly set or constructed from BASE_URL
    REDIRECT_URI = os.environ.get("REDIRECT_URI", BASE_URL + "/oauth2callback")

    # Service Account configuration for the Admin SDK
    SERVICE_ACCOUNT_FILE = os.environ.get("SERVICE_ACCOUNT_FILE", "student-password-manager-38ef54f19ebb.json")
    
    # Designated Admin user for domain-wide delegation
    ADMIN_USER = os.environ.get("ADMIN_USER", "evan.ayers@hart.k12.ga.us")
