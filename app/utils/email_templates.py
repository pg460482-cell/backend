import resend
from flask import current_app, request
from app.extensions import db
from app.models import Token, LoginAttempt
from datetime import datetime, timedelta, timezone
import secrets


def get_real_ip():
    """Proxy ke peeche bhi real IP milegi"""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def generate_token(user, token_type, expires_in=3600):
    """Generate cryptographically secure token"""
    # Purane tokens delete karo
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
    db.session.commit()

    return token_record, token


def send_verification_email(user):
    """
    Fix: user object leta hai — email aur token khud generate karta hai
    """
    try:
        resend.api_key = current_app.config.get('RESEND_API_KEY')

        # Debug logs
        current_app.logger.info(
            f"🔑 Key length: {len(resend.api_key) if resend.api_key else 'NONE'}"
        )

        # Token generate karo
        token_record, token = generate_token(user, 'verify', expires_in=86400)

        verify_url = (
            f"https://backend-2-hcso.onrender.com"
            f"/api/v1/auth/verify-email/{token}"
        )

        params: resend.Emails.SendParams = {
            "from":    "onboarding@resend.dev",
            "to":      [user.email],           # Fix: list hona chahiye
            "subject": "Verify Your Email",
            "html": f"""
<h2>Email Verification</h2>
<p>Hello {user.username},</p>
<p>Click below to verify your email:</p>
<a href="{verify_url}"
   style="background:#4CAF50;color:white;padding:10px 20px;
          text-decoration:none;border-radius:5px;">
    Verify Email
</a>
<p>This link expires in <b>24 hours</b>.</p>
<p>If you did not create an account, please ignore this email.</p>
"""
        }

        resend.Emails.send(params)
        current_app.logger.info(f"✅ Verification email sent to {user.email}")
        return True

    except Exception as e:
        current_app.logger.error(f"❌ Verification email error: {str(e)}")
        return False


def send_password_reset_email(user):
    """
    Fix: user object leta hai — email aur token khud generate karta hai
    """
    try:
        resend.api_key = current_app.config.get('RESEND_API_KEY')

        # Token generate karo
        token_record, token = generate_token(user, 'reset', expires_in=3600)

        reset_url = (
            f"https://backend-2-hcso.onrender.com"
            f"/api/v1/auth/reset-password"
        )

        params: resend.Emails.SendParams = {
            "from":    "onboarding@resend.dev",
            "to":      [user.email],           # Fix: list hona chahiye
            "subject": "Reset Your Password",
            "html": f"""
<h2>Password Reset</h2>
<p>Hello {user.username},</p>
<p>You requested to reset your password.</p>
<p>Use this token in the reset password form:</p>
<code style="background:#f4f4f4;padding:10px;display:block;
             font-size:16px;letter-spacing:1px;">
    {token}
</code>
<p>Or click the link below:</p>
<a href="{reset_url}?token={token}"
   style="background:#e53935;color:white;padding:10px 20px;
          text-decoration:none;border-radius:5px;">
    Reset Password
</a>
<p>This link expires in <b>1 hour</b>.</p>
<p>If you did not request this, please ignore this email.</p>
"""
        }

        resend.Emails.send(params)
        current_app.logger.info(f"✅ Reset email sent to {user.email}")
        return True

    except Exception as e:
        current_app.logger.error(f"❌ Reset email error: {str(e)}")
        return False


def log_login_attempt(email, ip_address, user_agent, success, user_id=None):
    """Login attempts log karo"""
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
        current_app.logger.error(f"Failed to log login attempt: {str(e)}")
