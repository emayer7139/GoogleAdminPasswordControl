import logging
import secrets
import time
from datetime import datetime

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError

from extensions import limiter
from services.google_admin import get_user_summary
from services.roles import get_role_for_user, get_school_from_ou
from services.storage import append_login_log, log_failed_login, get_theme_for_user

logger = logging.getLogger(__name__)

bp = Blueprint('auth', __name__)


@bp.route('/login')
def login_page():
    if 'google_id' in session:
        return redirect(url_for('main.index'))
    return render_template('login.html', dev_login_enabled=current_app.config.get('DEV_LOGIN_ENABLED'))


@bp.route('/login/google')
@limiter.limit('10 per minute')
def login_google():
    flow = Flow.from_client_config(
        {'web': {
            'client_id':     current_app.config['GOOGLE_CLIENT_ID'],
            'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
            'auth_uri':      'https://accounts.google.com/o/oauth2/auth',
            'token_uri':     'https://oauth2.googleapis.com/token',
            'redirect_uris': [current_app.config['REDIRECT_URI']],
        }},
        scopes=[
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ]
    )
    flow.redirect_uri = current_app.config['REDIRECT_URI']
    flow.oauth2session.trust_env = True

    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='select_account'
    )
    session['state'] = state
    return redirect(auth_url)


@bp.route('/oauth2callback')
@limiter.limit('10 per minute')
def oauth2callback():
    logger.info('[OAUTH2] Starting callback')
    try:
        state = session.get('state')
        session.clear()
        if state:
            session['state'] = state
        if not state or request.args.get('state') != state:
            raise ValueError('Invalid state parameter')

        flow = Flow.from_client_config(
            {'web': {
                'client_id':     current_app.config['GOOGLE_CLIENT_ID'],
                'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
                'auth_uri':      'https://accounts.google.com/o/oauth2/auth',
                'token_uri':     'https://oauth2.googleapis.com/token',
                'redirect_uris': [current_app.config['REDIRECT_URI']],
            }},
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile',
            ],
            state=state
        )
        flow.redirect_uri = current_app.config['REDIRECT_URI']
        flow.oauth2session.trust_env = True

        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        idinfo = id_token.verify_oauth2_token(
            creds.id_token, GoogleRequest(), current_app.config['GOOGLE_CLIENT_ID']
        )

        email = idinfo['email'].lower()
        name = idinfo.get('name', '')

        user_data = get_user_summary(email)
        role = get_role_for_user(email, user_data)
        if not role:
            log_failed_login(email, 'Role not permitted', ip=request.remote_addr)
            session.clear()
            flash('Only authorized staff may sign in.', 'danger')
            return redirect(url_for('auth.login_page'))

        session['google_id'] = idinfo['sub']
        session['user_info'] = {'email': email, 'name': name}
        session['csrf_token'] = secrets.token_hex(16)
        session['role'] = role
        session['orgUnitPath'] = user_data.get('orgUnitPath', '')
        session['school'] = get_school_from_ou(user_data.get('orgUnitPath', ''))
        session['theme'] = get_theme_for_user(email) or 'light'
        session['last_active'] = time.time()

        append_login_log({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'user': email,
            'outcome': 'Success',
            'ip': request.remote_addr or ''
        })

        return redirect(url_for('main.index'))

    except (ValueError, HttpError) as exc:
        log_failed_login('Unknown', f'OAuth2 error: {exc}', ip=request.remote_addr)
        session.clear()
        flash('Login failed. Please try again.', 'danger')
        return redirect(url_for('auth.login_page'))


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login_page'))


@bp.route('/login/dev')
def login_dev():
    if not current_app.config.get('DEV_LOGIN_ENABLED'):
        abort(404)

    email = request.args.get('email', current_app.config.get('DEV_LOGIN_EMAIL', 'dev@example.com')).lower()
    role = request.args.get('role', current_app.config.get('DEV_LOGIN_ROLE', 'global_admin'))

    session['google_id'] = f'dev:{email}'
    session['user_info'] = {'email': email, 'name': 'Developer'}
    session['csrf_token'] = secrets.token_hex(16)
    session['role'] = role
    session['orgUnitPath'] = '/Dev'
    session['school'] = 'Dev'
    session['theme'] = get_theme_for_user(email) or 'light'
    session['last_active'] = time.time()

    append_login_log({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': email,
        'outcome': 'Success (Dev Login)',
        'ip': request.remote_addr or ''
    })

    return redirect(url_for('main.index'))


@bp.route('/login/dev/teacher')
def login_dev_teacher():
    return _preset_dev_login('teacher', current_app.config.get('DEV_TEACHER_EMAIL', 'teacher.dev@example.com'))


@bp.route('/login/dev/media')
def login_dev_media():
    return _preset_dev_login('media_specialist', current_app.config.get('DEV_MEDIA_EMAIL', 'media.dev@example.com'))


def _preset_dev_login(role, email):
    if not current_app.config.get('DEV_LOGIN_ENABLED'):
        abort(404)
    session['google_id'] = f'dev:{email}'
    session['user_info'] = {'email': email, 'name': 'Developer'}
    session['csrf_token'] = secrets.token_hex(16)
    session['role'] = role
    session['orgUnitPath'] = '/Dev'
    session['school'] = 'Dev'
    session['theme'] = get_theme_for_user(email) or 'light'
    session['last_active'] = time.time()
    append_login_log({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': email,
        'outcome': f'Success (Dev Login: {role})',
        'ip': request.remote_addr or ''
    })
    return redirect(url_for('main.index'))
