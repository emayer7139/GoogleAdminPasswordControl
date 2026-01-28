FROM python:3.11-slim

# Install dependencies required for building Python packages
RUN apt-get update && apt-get install -y gcc

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
RUN chmod +x /app/run_gunicorn.sh

EXPOSE 5000

CMD ["/app/run_gunicorn.sh"]
