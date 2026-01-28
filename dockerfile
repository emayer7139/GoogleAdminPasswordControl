FROM python:3.11-slim

# Install dependencies required for building Python packages
RUN apt-get update && apt-get install -y gcc git && rm -rf /var/lib/apt/lists/*

ARG APP_VERSION=""
ARG GIT_SHA=""
ARG BUILD_TIME=""
ENV APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA} \
    BUILD_TIME=${BUILD_TIME}

WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy all project files into the container
COPY . .
RUN python - <<'PY'
import json
import os
import subprocess
from datetime import datetime, timezone

def run(args):
    try:
        return subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""

version = (os.environ.get("APP_VERSION") or "").strip()
commit = (os.environ.get("GIT_SHA") or "").strip()
build_time = (os.environ.get("BUILD_TIME") or "").strip()

if not commit:
    commit = run(["git", "rev-parse", "HEAD"])
if not version:
    version = run(["git", "describe", "--tags", "--always", "--dirty"]) or (commit[:7] if commit else "")
if not build_time:
    build_time = run(["git", "show", "-s", "--format=%cI", "HEAD"])
if not build_time:
    build_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

payload = {
    "version": version or "unknown",
    "commit": commit or "unknown",
    "build_time": build_time or "unknown",
}

with open("/app/build_info.json", "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
PY
RUN chmod +x /app/run_gunicorn.sh

EXPOSE 5000

CMD ["/app/run_gunicorn.sh"]
