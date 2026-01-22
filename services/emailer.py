import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app


def send_email(subject, body, recipients):
    config = current_app.config
    host = config.get('SMTP_HOST')
    port = config.get('SMTP_PORT', 587)
    user = config.get('SMTP_USER')
    password = config.get('SMTP_PASSWORD')
    sender = config.get('SMTP_FROM') or user
    use_tls = config.get('SMTP_USE_TLS', True)

    if not host or not sender or not recipients:
        raise RuntimeError('SMTP not configured')

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=15) as smtp:
        smtp.ehlo()
        if use_tls:
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg)
