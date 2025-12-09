#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------
# run_gunicorn.sh — boots your Flask app under Gunicorn
# ---------------------------------------------------

# Change to the directory where this script lives
cd "$(dirname "$0")"

echo "🔄 Starting Gunicorn on 127.0.0.1:5000 with 3 workers…"

exec gunicorn \
  --workers 3 \
  --bind 127.0.0.1:5000 \
  --access-logfile - \
  --error-logfile - \
  app:app

