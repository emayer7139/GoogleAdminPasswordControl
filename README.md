# ResetApp

ResetApp is a lightweight internal web app for Google Workspace to reset student passwords with role-based controls. It uses Google OAuth2 SSO, the Admin SDK, and (optionally) Google Classroom rosters.

## Roles and Permissions

- Teacher: can reset students in their Google Classroom rosters.
- Media Specialist: can reset students in the same school OU segment.
- Admin: full control over all students.
- Global Admin: full control over everything (super admin or listed as global admin).

## Features

- Google SSO for staff authentication
- Admin SDK integration with domain-wide delegation
- Classroom roster checks for teachers
- Role-based access controls
- Rate limiting and audit logs

## Requirements

- Python 3.9+
- Google Workspace super admin account
- Google Cloud project with:
  - OAuth 2.0 Client (Web)
  - Service account with domain-wide delegation
  - Admin SDK enabled
  - Classroom API enabled (for teacher rosters)

## Setup

### 1) Install dependencies

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Configure environment

Create or edit `.env` in the project root. Example placeholders:

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
BASE_URL=https://localhost:5000
SERVICE_ACCOUNT_FILE=C:\path\to\service-account.json
ADMIN_USER=superadmin@yourdomain.com
RESET_LIMIT=5

# Role OU prefixes
ROLE_OU_TEACHER_PREFIXES=/Staff/Teachers,/Staff/Faculty
ROLE_OU_MEDIA_PREFIXES=/Staff/Media Specialists,/Staff/Media

# Staff search OUs
STAFF_OU_PREFIXES=/Staff/District,/Staff/Faculty,/Staff/Long Term Subs,/Staff/School Admins,/Staff/Media Specialists

# OU segments to skip when deriving school name
SCHOOL_OU_SKIP_SEGMENTS=Teachers,Faculty,School Admins,Media Specialists,District,Long Term Subs

# Global admins (optional)
GLOBAL_ADMIN_EMAILS=
DEV_LOGIN_ENABLED=false
DEV_LOGIN_EMAIL=dev@example.com
DEV_LOGIN_ROLE=global_admin
DATABASE_URL=sqlite:///C:/path/to/GoogleAdminPasswordControl/data/resetapp.db
```

Global admins can be set via `GLOBAL_ADMIN_EMAILS` or stored in the `global_admins` database table
(seeded from the legacy JSON file on first run).

### 2a) Local SSL toggle

If you do not want a self-signed cert, set:

```env
USE_ADHOC_SSL=false
```

### 3) Domain-wide delegation scopes

Add these scopes to the service account in Google Admin Console:

- https://www.googleapis.com/auth/admin.directory.user
- https://www.googleapis.com/auth/admin.directory.user.readonly
- https://www.googleapis.com/auth/classroom.courses.readonly
- https://www.googleapis.com/auth/classroom.rosters.readonly

### 4) Run

```powershell
python app.py
```

Open `https://localhost:5000/login` and sign in.

### Dev Login (optional)

Enable developer login to bypass Google sign-in during local development:

```env
DEV_LOGIN_ENABLED=true
DEV_LOGIN_EMAIL=dev@example.com
DEV_LOGIN_ROLE=global_admin
DEV_TEACHER_EMAIL=teacher.dev@example.com
DEV_MEDIA_EMAIL=media.dev@example.com
```

Then visit:

```
https://localhost:5000/login/dev
```

Teacher and media specialist shortcuts:

```
https://localhost:5000/login/dev/teacher
https://localhost:5000/login/dev/media
```

You can override the email/role per request:

```
https://localhost:5000/login/dev?email=tester@yourdomain.com&role=admin
```

Set `DEV_LOGIN_ENABLED=false` to disable.

## Email notifications (optional)

ResetApp can send outage emails when `/status/notify` is called (for example by a cron job or uptime monitor).

Add to `.env`:

```env
STATUS_EMAIL_ENABLED=true
STATUS_EMAIL_RECIPIENTS=alerts@yourdomain.com
STATUS_EMAIL_COOLDOWN_MINUTES=30
STATUS_EMAIL_NOTIFY_ON_RECOVERY=true
STATUS_EMAIL_TOKEN=change-me
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=alerts@yourdomain.com
SMTP_PASSWORD=app-password-here
SMTP_FROM=alerts@yourdomain.com
```

Then call:

```
https://your-host/status/notify?token=change-me
```

If you use Gmail, create an app password for the sending account.

## Notes

- The app uses HTTPS with a self-signed cert for local runs.
- Audit logs, bug reports, and known issues are stored in the database (SQLite by default). Set `DATABASE_URL` for Postgres (requires `psycopg[binary]`).
- If you do not need Classroom checks, you can leave the Classroom scopes in place or remove them and update the teacher role behavior.
