FROM python:3.11-slim

# Install dependencies required for building Python packages
RUN apt-get update && apt-get install -y gcc

WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy all project files into the container
COPY . .
RUN chmod +x /app/run_gunicorn.sh

EXPOSE 5000

CMD ["/app/run_gunicorn.sh"]
