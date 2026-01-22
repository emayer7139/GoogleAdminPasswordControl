import time

from flask import current_app
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from services.cache import admin_api_cache

READONLY_SCOPE = 'https://www.googleapis.com/auth/admin.directory.user.readonly'
WRITE_SCOPE = 'https://www.googleapis.com/auth/admin.directory.user'


def _get_service(scopes):
    creds = service_account.Credentials.from_service_account_file(
        current_app.config['SERVICE_ACCOUNT_FILE'],
        scopes=scopes
    ).with_subject(current_app.config['ADMIN_USER'])
    return build('admin', 'directory_v1', credentials=creds)


def get_user_summary(email):
    cache_key = f'summary:{email.lower()}'
    cached = admin_api_cache.get(cache_key)
    if cached:
        return cached

    svc = _get_service([READONLY_SCOPE])
    for attempt in range(4):
        try:
            user = svc.users().get(
                userKey=email,
                fields='orgUnitPath,isAdmin,primaryEmail'
            ).execute()
            admin_api_cache[cache_key] = user
            return user
        except HttpError as exc:
            status = getattr(exc, 'status_code', None)
            if status in (403, 404):
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError('Admin API failed after retries')


def get_user(email):
    svc = _get_service([READONLY_SCOPE])
    return svc.users().get(userKey=email).execute()


def update_password(email, new_password):
    svc = _get_service([WRITE_SCOPE])
    return svc.users().update(
        userKey=email,
        body={'password': new_password, 'changePasswordAtNextLogin': True}
    ).execute()


def search_users(query, max_results=50):
    svc = _get_service([READONLY_SCOPE])
    toks = query.split()
    results = []
    for field in ('givenName', 'familyName', 'email'):
        resp = svc.users().list(
            customer='my_customer',
            query=f"{field}:{toks[0]}*",
            maxResults=max_results
        ).execute()
        results.extend(resp.get('users', []))
    return results


def search_staff(query, staff_prefixes, max_results=50):
    candidates = search_users(query, max_results=max_results)
    unique = {u['primaryEmail']: u for u in candidates if u.get('primaryEmail')}
    return [
        u for u in unique.values()
        if any(u.get('orgUnitPath', '').startswith(prefix) for prefix in staff_prefixes)
    ]
