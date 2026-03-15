import resend
from flask import current_app

def send_verification_email(user_email, token):
    try:
        resend.api_key = current_app.config.get('RESEND_API_KEY')
        
        # ← Debug lines add karo
        current_app.logger.info(f"🔑 Key length: {len(resend.api_key) if resend.api_key else 'NONE'}")
        current_app.logger.info(f"🔑 Key starts: {resend.api_key[:5] if resend.api_key else 'NONE'}")
        
        verify_url = f"https://backend-2-hcso.onrender.com/api/v1/auth/verify-email/{token}"
        
        params = {
            "from": "onboarding@resend.dev",
            "to": user_email,
            "subject": "Verify Your Email",
            "html": f"""
<h2>Email Verification</h2>
<p>Click below to verify your email:</p>
<a href="{verify_url}" style="background:#4CAF50;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">
    Verify Email
</a>
<p>Expires in <b>24 hours</b>.</p>
"""
        }
        resend.Emails.send(params)
        current_app.logger.info(f"✅ Email sent to {user_email}")
        return True
    except Exception as e:
        current_app.logger.error(f"❌ Email error: {str(e)}")
        return False


def send_password_reset_email(user_email, token):
    try:
        resend.api_key = current_app.config.get('RESEND_API_KEY')
        
        params = {
            "from": "onboarding@resend.dev",
            "to": user_email,
            "subject": "Reset Your Password",
            "html": f"""
<h2>Password Reset</h2>
<p>Your password reset token:</p>
<code style="background:#f4f4f4;padding:10px;display:block;">{token}</code>
<p>Expires in <b>1 hour</b>.</p>
"""
        }
        resend.Emails.send(params)
        current_app.logger.info(f"✅ Reset email sent to {user_email}")
        return True
    except Exception as e:
        current_app.logger.error(f"❌ Reset email error: {str(e)}")
        return False
