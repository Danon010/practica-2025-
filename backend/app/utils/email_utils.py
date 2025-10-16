import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from app.config import settings
from .templates import verification_email_html, password_reset_email_html, scan_completed_email_html

logger = logging.getLogger(__name__)

async def send_email(to: str, subject: str, body: str):
    if not all([settings.SMTP_HOST, settings.SMTP_PORT, settings.SMTP_USER, settings.SMTP_PASSWORD]):
        logger.warning("SMTP settings not configured - email sending disabled")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = settings.EMAIL_FROM
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Email sent to {to} with subject: {subject}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {str(e)}")
        return False

async def send_verification_email(email: str, token: str):
    subject = "Verify your email address - Vulnerability Scanner"
    verification_url = f"http://localhost:3000/verify-email?token={token}"
    body = verification_email_html.format(verification_url=verification_url)
    return await send_email(email, subject, body)

async def send_password_reset_email(email: str, token: str):
    subject = "Password Reset Request - Vulnerability Scanner"
    reset_url = f"http://localhost:3000/reset-password?token={token}"
    body = password_reset_email_html.format(reset_url=reset_url)
    return await send_email(email, subject, body)

async def send_scan_completed_email(email: str, target: str, scan_results: dict):
    subject = f"Scan completed for {target} - Vulnerability Scanner"
    body = scan_completed_email_html.format(
        target=target,
        total_vulnerabilities=scan_results.get('total_vulnerabilities', 0),
        critical_count=scan_results.get('critical_count', 0),
        high_count=scan_results.get('high_count', 0),
        medium_count=scan_results.get('medium_count', 0),
        low_count=scan_results.get('low_count', 0)
    )
    return await send_email(email, subject, body)
