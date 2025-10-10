from db import SessionLocal
import os, smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def send_email(to, subject, body):
    load_dotenv()
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = os.getenv("EMAIL_USER")
    msg["To"] = to
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASS"))
        server.send_message(msg)
