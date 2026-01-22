from flask import current_app

from services.storage import load_admins, load_global_admins

ROLE_TEACHER = 'teacher'
ROLE_MEDIA_SPECIALIST = 'media_specialist'
ROLE_ADMIN = 'admin'
ROLE_GLOBAL_ADMIN = 'global_admin'


def get_role_for_user(email, user_data):
    email = (email or '').lower()
    is_super_admin = bool(user_data.get('isAdmin'))
    if is_super_admin:
        return ROLE_GLOBAL_ADMIN

    config_globals = current_app.config.get('GLOBAL_ADMIN_EMAILS', set())
    if email in config_globals or email in load_global_admins():
        return ROLE_GLOBAL_ADMIN

    if email in load_admins():
        return ROLE_ADMIN

    ou_path = user_data.get('orgUnitPath', '')
    prefixes = current_app.config.get('ROLE_OU_PREFIXES', {})

    if _ou_matches(ou_path, prefixes.get(ROLE_MEDIA_SPECIALIST, [])):
        return ROLE_MEDIA_SPECIALIST
    if _ou_matches(ou_path, prefixes.get(ROLE_TEACHER, [])):
        return ROLE_TEACHER

    return None


def _ou_matches(ou_path, prefixes):
    for prefix in prefixes:
        if ou_path.startswith(prefix):
            return True
    return False


def get_school_from_ou(ou_path):
    if not ou_path:
        return ''
    skip = current_app.config.get('SCHOOL_OU_SKIP_SEGMENTS', set())
    segments = [seg for seg in ou_path.split('/') if seg]
    for seg in segments:
        lower = seg.strip().lower()
        if lower in ('students', 'staff'):
            continue
        if lower in skip:
            continue
        return seg
    return ''
