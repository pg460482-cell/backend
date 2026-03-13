from flask_mail import Message
from app.extensions import mail
from flask import current_app
import threading

def send_email_async(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Async email error: {str(e)}")

def send_verification_email(user_email, token):
    try:
        app = current_app._get_current_object()
        verify_url = f"https://backend-2-hcso.onrender.com/api/v1/auth/verify-email/{token}"
        
        msg = Message(
            subject="Verify Your Email",
            recipients=[user_email],
            body=f"Please verify your email: {verify_url}\n\nExpires in 24 hours.",
            html=f"""
<h2>Email Verification</h2>
<p>Click below to verify your email:</p>
<a href="{verify_url}" style="background:#4CAF50;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">
    Verify Email
</a>
<p>Expires in <b>24 hours</b>.</p>
"""
        )
        # ✅ Background mein bhejo — request block nahi hogi
        thread = threading.Thread(target=send_email_async, args=(app, msg))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        current_app.logger.error(f"Email error: {str(e)}")
        return False


def send_password_reset_email(user_email, token):
    try:
        app = current_app._get_current_object()
        
        msg = Message(
            subject="Reset Your Password",
            recipients=[user_email],
            body=f"Your password reset token:\n\n{token}\n\nExpires in 1 hour.",
            html=f"""
<h2>Password Reset</h2>
<p>Your password reset token:</p>
<code style="background:#f4f4f4;padding:10px;display:block;">{token}</code>
<p>Expires in <b>1 hour</b>.</p>
"""
        )
        thread = threading.Thread(target=send_email_async, args=(app, msg))
        thread.daemon = True
        thread.start()
        return True
    except Exception as e:
        current_app.logger.error(f"Email error: {str(e)}")
        return False
