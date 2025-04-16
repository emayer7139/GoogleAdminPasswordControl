import os
# Allow insecure transport for local development (HTTP only)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

import sys
import logging
import secrets
import string
from functools import wraps

from flask import Flask, redirect, url_for, session, request, render_template, flash
from google.oauth2 import id_token, service_account
from google_auth_oauthlib.flow import Flow
import requests
from googleapiclient.discovery import build
# Import Request from google.auth.transport.requests for token verification
from google.auth.transport.requests import Request as GoogleRequest

# Load configuration from config.py (which in turn loads from .env if using python-dotenv)
from config import Config

# Set up logging to standard output for debugging purposes
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logger = logging.getLogger(__name__)

# Initialize Flask app with configuration settings
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config["SECRET_KEY"]

def generate_password(length=12):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "google_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session.get("user_info"))

@app.route("/login")
def login():
    try:
        # Set up the OAuth 2.0 flow configuration
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": app.config["GOOGLE_CLIENT_ID"],
                    "client_secret": app.config["GOOGLE_CLIENT_SECRET"],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [app.config["REDIRECT_URI"]],
                }
            },
            scopes=[
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile"
            ]
        )
        flow.redirect_uri = app.config["REDIRECT_URI"]

        # Generate authorization URL and state to mitigate CSRF
        authorization_url, state = flow.authorization_url(
            prompt='consent',
            include_granted_scopes='true',
            access_type='offline'
        )
        # Store the generated state in the session
        session['state'] = state
        logger.debug("Login initiated. Generated state: %s", state)
        logger.debug("Redirecting to: %s", authorization_url)
        return redirect(authorization_url)
    except Exception as e:
        logger.error("Error in /login route: %s", e, exc_info=True)
        return "An error occurred during login.", 500

@app.route("/oauth2callback")
def oauth2callback():
    try:
        # Log the full authorization response URL and query parameters for debugging
        authorization_response = request.url
        logger.debug("OAuth callback URL: %s", authorization_response)
        logger.debug("Query parameters: %s", request.args)

        # Retrieve and compare state values to protect against CSRF
        session_state = session.get('state')
        received_state = request.args.get('state')
        logger.debug("Session state: %s, Received state: %s", session_state, received_state)
        if not session_state or session_state != received_state:
            logger.error("CSRF Warning: State mismatch. Session state: %s, Received state: %s", session_state, received_state)
            return "State mismatch. Possible CSRF attack.", 400

        # Reinitialize the flow with the stored state
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": app.config["GOOGLE_CLIENT_ID"],
                    "client_secret": app.config["GOOGLE_CLIENT_SECRET"],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [app.config["REDIRECT_URI"]],
                }
            },
            scopes=[
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile"
            ],
            state=session_state
        )
        flow.redirect_uri = app.config["REDIRECT_URI"]

        # Ensure the authorization code is present in the callback query parameters
        if 'code' not in request.args:
            logger.error("Missing code parameter in OAuth callback.")
            return "Missing code parameter.", 400

        # Fetch the token using the authorization response
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials

        # Verify the token using GoogleRequest from google.auth.transport.requests
        try:
            id_info = id_token.verify_oauth2_token(
                credentials.id_token,
                GoogleRequest(),
                app.config["GOOGLE_CLIENT_ID"]
            )
        except Exception as token_err:
            logger.error("Token verification failed: %s", token_err, exc_info=True)
            return "Token verification failed.", 400

        # Store user information from the verified token into the session
        session['google_id'] = id_info.get("sub")
        session['user_info'] = {
            "email": id_info.get("email"),
            "name": id_info.get("name")
        }
        logger.debug("User authenticated successfully: %s", session.get('user_info'))
        return redirect(url_for("index"))
    except Exception as e:
        logger.error("Error in /oauth2callback route: %s", e, exc_info=True)
        return "Authentication failed.", 400

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/reset", methods=['GET', 'POST'])
@login_required
def reset():
    if request.method == 'POST':
        student_email = request.form.get("student_email")
        if not student_email:
            flash("Please enter a student email.", "danger")
            return redirect(url_for("reset"))
        try:
            # Load service account credentials and delegate authority
            credentials = service_account.Credentials.from_service_account_file(
                app.config["SERVICE_ACCOUNT_FILE"],
                scopes=['https://www.googleapis.com/auth/admin.directory.user']
            )
            delegated_credentials = credentials.with_subject(app.config["ADMIN_USER"])
            service = build('admin', 'directory_v1', credentials=delegated_credentials)

            # Retrieve teacher and student details from the Admin API
            teacher = service.users().get(userKey=session['user_info']['email']).execute()
            student = service.users().get(userKey=student_email).execute()
            teacher_org = teacher.get('orgUnitPath')
            student_org = student.get('orgUnitPath')

            # Verify both teacher and student belong to the same organizational unit
            if teacher_org != student_org:
                flash("You do not have permission to reset this student's password.", "danger")
                return redirect(url_for("reset"))

            # Generate a new secure password and update the student's account
            new_password = generate_password(12)
            body = {
                "password": new_password,
                "changePasswordAtNextLogin": True
            }
            service.users().update(userKey=student_email, body=body).execute()

            flash("Password reset successful. The new password is displayed below. It will disappear in 2 minutes.", "success")
            return render_template("reset.html", new_password=new_password, student_email=student_email)
        except Exception as e:
            logger.error("Error in /reset route: %s", e, exc_info=True)
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("reset"))
    return render_template("reset.html", new_password=None)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
