import time
from datetime import datetime
from functools import wraps

from flask import abort, flash, redirect, request, session, url_for

from services.roles import ROLE_ADMIN, ROLE_GLOBAL_ADMIN
from services.storage import log_failed_login


def login_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if 'google_id' not in session:
            log_failed_login(session.get('user_info', {}).get('email', 'Unknown'), 'Not logged in', ip=request.remote_addr)
            return redirect(url_for('auth.login_page'))
        last_active = session.get('last_active')
        if last_active:
            now_ts = time.time()
            if isinstance(last_active, (int, float)):
                last_ts = float(last_active)
            else:
                try:
                    last_ts = float(last_active)
                except (TypeError, ValueError):
                    last_ts = now_ts
            if (now_ts - last_ts) > 3600:
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('auth.login_page'))
        session['last_active'] = time.time()
        return func(*args, **kwargs)
    return decorated


def role_required(allowed_roles):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            role = session.get('role')
            if role not in allowed_roles:
                abort(403)
            session.modified = True
            return func(*args, **kwargs)
        return wrapped
    return decorator


def admin_required(func):
    return role_required({ROLE_ADMIN, ROLE_GLOBAL_ADMIN})(func)
