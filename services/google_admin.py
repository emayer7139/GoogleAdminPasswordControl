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
    raw = (query or '').strip()
    if not raw:
        return []
    cache_key = f"search:{raw.lower()}:{max_results}"
    cached = admin_api_cache.get(cache_key)
    if cached is not None:
        return cached
    fields = 'users(primaryEmail,name(givenName,familyName),orgUnitPath),nextPageToken'
    if '@' in raw:
        try:
            user = svc.users().get(
                userKey=raw,
                fields='primaryEmail,name(givenName,familyName),orgUnitPath'
            ).execute()
            admin_api_cache[cache_key] = [user]
            return [user]
        except HttpError:
            raw = raw.split('@', 1)[0].strip()
            if not raw:
                return []
    toks = raw.split()
    if not toks:
        return []
    term = toks[0]
    results = []
    try:
        resp = svc.users().list(
            customer='my_customer',
            query=f"givenName:{term}* OR familyName:{term}* OR email:{term}*",
            maxResults=max_results,
            fields=fields
        ).execute()
        results = resp.get('users', [])
    except HttpError:
        results = []

    if not results:
        for field in ('givenName', 'familyName', 'email'):
            resp = svc.users().list(
                customer='my_customer',
                query=f"{field}:{term}*",
                maxResults=max_results,
                fields=fields
            ).execute()
            results.extend(resp.get('users', []))
    admin_api_cache[cache_key] = results
    return results


def search_staff(query, staff_prefixes, max_results=50):
    candidates = search_users(query, max_results=max_results)
    unique = {u['primaryEmail']: u for u in candidates if u.get('primaryEmail')}
    return [
        u for u in unique.values()
        if any(u.get('orgUnitPath', '').startswith(prefix) for prefix in staff_prefixes)
    ]
