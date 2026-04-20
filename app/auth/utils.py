from flask import url_for, current_app as app, request
from flask_mail import Message
from app.extensions import mail, db
from app.models import Token, LoginAttempt
from datetime import datetime, timedelta, timezone
import secrets
import re


def get_real_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def generate_token(user, token_type, expires_in=3600):
    """Generate cryptographically secure token"""
    Token.query.filter_by(
        user_id=user.id,
        token_type=token_type
    ).delete(synchronize_session=False)

    token      = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    token_record = Token(
        token=token,
        token_type=token_type,
        expires_at=expires_at,
        user_id=user.id,
        device_info=request.headers.get('User-Agent', '')[:200] if request else '',
        ip_address=get_real_ip() if request else ''
    )

    db.session.add(token_record)
    db.session.flush()                        # commit nahi — caller commit karega

    return token_record, token


def send_email(subject, recipients, body, html=None):
    try:
        msg = Message(
            subject=subject,
            recipients=recipients,
            body=body,
            html=html,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)
        app.logger.info(f"Email sent to {recipients}")
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email: {str(e)}")
        return False


def send_verification_email(user):
    """User object lo, token khud generate karo"""
    token_record, token = generate_token(user, 'verify', expires_in=86400)
    verification_url    = url_for('auth.verify_email', token=token, _external=True)

    body = f"""Hello {user.username},

Thank you for registering! Please verify your email by clicking the link below:

{verification_url}

This link will expire in 24 hours.
If you did not create an account, please ignore this email.

Best regards,
{app.config['API_TITLE']} Team"""

    return send_email(
        subject="Verify Your Email",
        recipients=[user.email],
        body=body
    )


def send_password_reset_email(user):
    """User object lo, token khud generate karo"""
    token_record, token = generate_token(user, 'reset', expires_in=3600)
    reset_url           = url_for('auth.reset_password', token=token, _external=True)

    body = f"""Hello {user.username},

You requested to reset your password. Click the link below to reset it:

{reset_url}

This link will expire in 1 hour.
If you did not request a password reset, please ignore this email.

Best regards,
{app.config['API_TITLE']} Team"""

    return send_email(
        subject="Reset Your Password",
        recipients=[user.email],
        body=body
    )


def log_login_attempt(email, ip_address, user_agent, success, user_id=None):
    """Login attempts log karo — alag try/except mein"""
    try:
        attempt = LoginAttempt(
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            user_id=user_id
        )
        db.session.add(attempt)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to log login attempt: {str(e)}")


def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    checks = [
        (r'[A-Z]',     "Password must contain at least one uppercase letter"),
        (r'[a-z]',     "Password must contain at least one lowercase letter"),
        (r'\d',        "Password must contain at least one number"),
        (r'[@$!%*?&]', "Password must contain at least one special character (@$!%*?&)")
    ]

    for pattern, message in checks:
        if not re.search(pattern, password):
            return False, message

    return True, ""


def validate_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
