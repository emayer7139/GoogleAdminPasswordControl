#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------
# run_gunicorn.sh -- boots your Flask app under Gunicorn
# ---------------------------------------------------

# Change to the directory where this script lives
cd "$(dirname "$0")"

WORKERS="${WEB_CONCURRENCY:-${GUNICORN_WORKERS:-3}}"
echo "Starting Gunicorn on 0.0.0.0:5000 with ${WORKERS} workers..."

exec gunicorn \
  --workers "${WORKERS}" \
  --bind 0.0.0.0:5000 \
  --access-logfile - \
  --error-logfile - \
  app:app
