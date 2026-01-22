import logging

from flask import current_app
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from services.cache import classroom_roster_cache

logger = logging.getLogger(__name__)

COURSE_SCOPES = [
    'https://www.googleapis.com/auth/classroom.courses.readonly',
    'https://www.googleapis.com/auth/classroom.rosters.readonly'
]


def _get_classroom_service(subject_email):
    creds = service_account.Credentials.from_service_account_file(
        current_app.config['SERVICE_ACCOUNT_FILE'],
        scopes=COURSE_SCOPES
    ).with_subject(subject_email)
    return build('classroom', 'v1', credentials=creds)


def get_teacher_roster_emails(teacher_email):
    cache_key = f'roster:{teacher_email.lower()}'
    cached = classroom_roster_cache.get(cache_key)
    if cached is not None:
        return cached

    service = _get_classroom_service(teacher_email)
    students = set()

    try:
        page_token = None
        while True:
            courses_resp = service.courses().list(
                teacherId=teacher_email,
                courseStates=['ACTIVE'],
                pageToken=page_token
            ).execute()
            for course in courses_resp.get('courses', []):
                course_id = course.get('id')
                if not course_id:
                    continue
                _add_course_students(service, course_id, students)
            page_token = courses_resp.get('nextPageToken')
            if not page_token:
                break
    except HttpError as exc:
        logger.error('Classroom roster error for %s: %s', teacher_email, exc)
        raise

    classroom_roster_cache[cache_key] = students
    return students


def _add_course_students(service, course_id, students):
    page_token = None
    while True:
        resp = service.courses().students().list(
            courseId=course_id,
            pageToken=page_token
        ).execute()
        for entry in resp.get('students', []):
            email = entry.get('profile', {}).get('emailAddress')
            if email:
                students.add(email.lower())
        page_token = resp.get('nextPageToken')
        if not page_token:
            break
