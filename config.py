import os
from dotenv import load_dotenv

# pull in that .env file
load_dotenv()

class Config:
    SECRET_KEY            = os.getenv("FLASK_SECRET_KEY")
    GOOGLE_CLIENT_ID      = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET  = os.getenv("GOOGLE_CLIENT_SECRET")
    BASE_URL              = os.getenv("BASE_URL")
    REDIRECT_URI          = os.getenv("REDIRECT_URI")
    SERVICE_ACCOUNT_FILE  = os.getenv("SERVICE_ACCOUNT_FILE")
    ADMIN_USER            = os.getenv("ADMIN_USER")

