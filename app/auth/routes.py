from flask import request,jsonify,current_app as app
from flask_jwt_extended import(
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from app.extensions import db,bcrypt,limiter
from app.auth import bp
from app.models import User,Token
from datetime import datetime,timedelta
from sqlalchemy import or_
import re
import secrets
def validate_email(email):
    pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.match(pattern,email)is not None
def validate_password(password):
    if len(password)<8:
        return False,"Password must be at least 8 characters long"
    if not re.search(r'[A-Z]',password):
        return False,"Password must be contain at least one uppercase letter"
    if not re.search(r'[a-z]',password):
        return False,"Password must be contain at least one lowercase letter "
    if not re.search(r'[0-9]',password):
        return False,"Password must contain at least one number"
    if not re.search(r'[!@#$%^&*()<>?{}/:]',password):
        return False,"Password must contain at least one special character"
    return True,""
def sanitize_input(text):
    if text:
        return re.sub(r'[<>&\']','',text)
    return text
@bp.route('/register',methods=['POST'])
@limiter.limit("5 per hour")
def register():
    data=request.get_json()
    if not data:
        return jsonify({'error':'No data provided '}),400
    email=data.get('email','').strip().lower()
    username=sanitize_input(data.get('username','').strip())
    password=data.get('password','')
    if not email or not username or not password:
        return jsonify({'error':'Email,username and password are required'}),400
    if not validate_email(email):
        return jsonify({'error':'Invalid email format'}),400
    is_valid,msg=validate_password(password)
    if  not is_valid:
        return jsonify({'error':msg}),400
    if len(username)<3 or len(username)>20:
        return jsonify({'error':'Username must be between 3-20 characters'}),400
    if User.query.filter_by(email=email).first():

    

        return jsonify({'error':'Email already registered'}),409
    if User.query.filter_by(username=username).first():
        return jsonify({'error':'username already taken'}),409
    hashed_password=bcrypt.generate_password_hash(password).decode('utf-8')
    user=User(
        username=username,
        email=email,
        password_hash=hashed_password,
        is_verified=False
    )
    try:
        db.session.add(user)
        db.session.flush()
        verify_token=create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(hours=24),
            additional_claims={'type':'email_verification'}
        )
        token_record=Token(
            token=verify_token,
            token_type='verify',
            expires_at=datetime.utcnow()+timedelta(hours=24),
            user_id=user.id,
            device_info=request.headers.get('User-Agent','Unknown')[:200],
            ip_address=request.remote_addr
        )
        db.session.add(token_record)
        db.session.commit()
        return jsonify({
            'message':'Registration successful.please verify your email',
            'user_id':user.id
        }),201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Registration error:{str(e)}")
        return jsonify({'error':'Internal server error'}),500
        
        
# # ================ LOGIN ================

@bp.route('/login',methods=['POST'])
@limiter.limit("10 per minutes")
def login():
    data=request.get_json()
    if not data:
        return jsonify({'error':'Email and password are required'}),400
    email=data.get('email','').strip().lower()
    password=data.get('password','')
    if not email or not password:
        return jsonify({'error':'Email and password are required'}),400
    user=User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash,password):
        return jsonify({'error':'Invalid email or password'}),401
    if not user. is_verified:
        return jsonify({'error':'Please verify your email first'}),403
    
    access_token=create_access_token(
        identity=user.id,
        expires_delta=timedelta(minutes=15),
        additional_claims={
            'username':user.username,
            'email':user.email
        }

    )
    refresh_token=create_refresh_token(
        identity=user.id,
        additional_claims={'type':'refresh'}

    )
    token_record=Token(
        token=refresh_token,
        token_type='refresh',
        expires_at=datetime.utcnow()+timedelta(days=30),
        user_id=user.id,
        device_info=request.headers.get('User-Agent','Unknown')[:200],
        ip_address=request.remote_addr
    )
    try:
        db.session.add(token_record)
        db.session.commit()
        return jsonify({
            'access_token':access_token,
            'refresh_token':refresh_token,
            'token_type':'Bearer',
            'expires_in':900,
            'user':{
                'id':user.id,
                'username':user.username,
                'email':user.email,
                'is_verified':user.is_verified,
                'created_at':user.created_at.isoformat()if user.created_at else None


            }
        }),200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Login error:{str(e)}")
        return jsonify({'error':'Internal server error'}),500



# ================ REFRESH TOKEN ================
@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)  # Fixed: proper refresh token requirement
@limiter.limit("10 per minute")
def refresh():
    current_user_id = get_jwt_identity()
    
    # Get refresh token from authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Invalid authorization header'}), 401
    
    old_refresh_token = auth_header.split(' ')[1]
    
    # Verify token in database
    token_record = Token.query.filter_by(
        token=old_refresh_token,
        token_type='refresh',
        is_used=False
    ).first()
    
    if not token_record or token_record.is_expired():
        return jsonify({'error': 'Invalid or expired refresh token'}), 401
    
    user = token_record.user
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Mark old token as used
    token_record.is_used = True
    token_record.revoked_at = datetime.utcnow()  # Fixed: added ()
    
    # Create new tokens
    new_access_token = create_access_token(
        identity=user.id,
        expires_delta=timedelta(minutes=15)
    )
    
    new_refresh_token = create_refresh_token(identity=user.id)
    
    # Store new refresh token
    new_token_record = Token(
        token=new_refresh_token,
        token_type='refresh',
        expires_at=datetime.utcnow() + timedelta(days=30),
        user_id=user.id,
        device_info=request.headers.get('User-Agent', 'Unknown')[:200],
        ip_address=request.remote_addr
    )
    
    try:
        db.session.add(new_token_record)
        db.session.commit()
        
        return jsonify({
            'access_token': new_access_token,  # Fixed: removed space
            'refresh_token': new_refresh_token,
            'token_type': 'Bearer',
            'expires_in': 900
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Refresh error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@bp.route('/verify-email/<token>', methods=['GET'])
@limiter.limit("10 per minute")
def verify_email(token):
    if not token:
        return jsonify({'error': 'Token is required'}), 400
    
    token_record = Token.query.filter_by(
        token=token,
        token_type='verify',
        is_used=False
    ).first()
    
    if not token_record:
        return jsonify({'error': 'Invalid verification token'}), 400
    
    if token_record.is_expired():
        return jsonify({'error': 'Verification token has expired'}), 400
    
    user = token_record.user
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Verify user
    user.is_verified = True
    token_record.is_used = True
    token_record.revoked_at = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify({
            'message': 'Email verified successfully',
            'user': {
                'id': user.id,
                'email': user.email,
                'is_verified': user.is_verified
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Email verification error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# ================ FORGOT PASSWORD ================
@bp.route('/forgot-password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    data = request.get_json()

    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400

    email = data['email'].strip().lower()
    user = User.query.filter_by(email=email).first()

    if user:
        try:
            # 🔐 1️⃣ Delete old reset tokens
            Token.query.filter_by(
                user_id=user.id,
                token_type='reset'
            ).delete()
            db.session.commit()

            # 🔐 2️⃣ Generate secure random reset token
            reset_token = secrets.token_urlsafe(32)

            # ⏳ 3️⃣ Set expiry (1 hour)
            expires_at = datetime.utcnow() + timedelta(hours=1)

            # 💾 4️⃣ Store token in DB
            token_record = Token(
                token=reset_token,
                token_type='reset',
                expires_at=expires_at,
                user_id=user.id,
                device_info=request.headers.get('User-Agent', 'Unknown')[:200],
                ip_address=request.remote_addr,
                is_used=False
            )

            db.session.add(token_record)
            db.session.commit()

            # 📝 5️⃣ Log token for testing (remove in production)
            app.logger.info(f"Password reset token created for {email}")
            app.logger.info(f"🔐 Reset token: {reset_token}")  # 👈 YEH LINE ADD KARO
            app.logger.info(f"⏳ Expires at: {expires_at}")

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Forgot password error: {str(e)}")
    
    return jsonify({
        'message': 'If an account exists with this email, you will receive a password reset link shortly'
    }), 200
# ================ RESET PASSWORD ================
@bp.route('/reset-password', methods=['POST'])
@limiter.limit("5 per hour")
def reset_password():  # Fixed: function name spelling
    data = request.get_json()
    if not data or 'token' not in data or 'password' not in data:
        return jsonify({'error': 'Token and new password are required'}), 400
    
    token = data['token']
    new_password = data['password']
    
    # Validate password
    is_valid, password_message = validate_password(new_password)
    if not is_valid:
        return jsonify({'error': password_message}), 400
    
    # Find token
    token_record = Token.query.filter_by(
        token=token,
        token_type='reset',
        is_used=False
    ).first()
    
    if not token_record or token_record.is_expired():
        return jsonify({'error': 'Invalid or expired reset token'}), 400
    
    user = token_record.user
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Update password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password_hash = hashed_password
    
    # Mark token as used
    token_record.is_used = True
    token_record.revoked_at = datetime.utcnow()
    
    # Revoke all refresh tokens (force re-login)
    Token.query.filter_by(
        user_id=user.id,
        token_type='refresh',
        is_used=False
    ).update({
        'is_used': True,
        'revoked_at': datetime.utcnow()
    })
    
    try:
        db.session.commit()
        return jsonify({'message': 'Password reset successfully. Please login with your new password.'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Reset password error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
@bp.route('/logout',methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def logout():
    current_user_id=get_jwt_identity()
    try:
        jti=get_jwt()['jti']
        expires=get_jwt()['exp']
        expires_at=datetime.fromtimestamp(expires)
        blacklisted_token=Token(
            token=jti,
            token_type='access',
            expires_at=expires_at,
            user_id=current_user_id,
            is_used=True,
            revoked_at=datetime.utcnow(),
            device_info=request.headers.get('User-Agent','Unknown')[:200],
            ip_address=request.remote_addr

        )
        db.session.add(blacklisted_token)
    except Exception as e:
        app.logger.error(f"Access token blacklist error:{str(e)}")
    
    Token.query.filter_by(
        user_id=current_user_id,
        token_type='refresh',
        is_used=False
    ).update({
        'is_used':True,
        'revoked_at':datetime.utcnow()
    })
    try:
        db.session.commit()
        return jsonify({'message':'Logged out successfully'}),200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Logout error:{str(e)}")
        return jsonify({'error':'Internal server error'}),500



 # ================ GET PROFILE ================
@bp.route('/profile', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
def get_profile():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_verified': user.is_verified,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'updated_at': user.updated_at.isoformat() if hasattr(user, 'updated_at') and user.updated_at else None
    }), 200

# ================ UPDATE PROFILE ================
@bp.route('/profile', methods=['PUT'])
@jwt_required()
@limiter.limit("10 per minute")
def update_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    updated = False
    
    # Update username
    if 'username' in data:
        new_username = sanitize_input(data['username'].strip())

        if len(new_username) < 3 or len(new_username) > 20:
            return jsonify({'error': 'Username must be between 3-20 characters'}), 400

        if not re.match(r'^[A-Za-z][A-Za-z0-9._]*$', new_username):
            return jsonify({
                'error': 'Username must start with a letter and contain only letters, numbers, dots, and underscores'
            }), 400

        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': 'Username already taken'}), 409

        user.username = new_username
        updated = True

    # Update email
    if 'email' in data:
        new_email = data['email'].strip().lower()

        if not validate_email(new_email):
            return jsonify({'error': 'Invalid email format'}), 400

        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': 'Email already registered'}), 409

        user.email = new_email
        user.is_verified = False  # Require re-verification
        updated = True
        
        # TODO: Send new verification email

    if not updated:
        return jsonify({'error': 'No valid fields to update'}), 400

    try:
        db.session.commit()
        return jsonify({
            'message': 'Profile updated successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_verified': user.is_verified
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Profile update error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

# ================ CHANGE PASSWORD ================


@bp.route('/change-password',methods=['POST'])
@jwt_required()
@limiter.limit("5 per hour")
def change_password():
    current_user_id=get_jwt_identity()
    user=User.query.get(current_user_id)

    if not user:
        return jsonify({'error':'User not found'}),404
    data=request.get_json()
    if not data or 'current_password' not in data or 'new_password'not in data:
        return jsonify({'error':'Current password and new password are required'}),400
    
    current_password=data['current_password']
    new_password=data['new_password']

  

    if not bcrypt.check_password_hash(user.password_hash,current_password):
        return jsonify({'error':'Current password is incorrect'}),401
    is_valid, message=validate_password(new_password)
    if not is_valid:
        return jsonify({'error':message}),400
    user.password_hash=bcrypt.generate_password_hash(new_password).decode('utf-8')
    Token.query.filter_by(
        user_id=user.id,
        token_type='refresh',
        is_used=False
    ).update({
        'is_used':True,
        'revoked_at':datetime.utcnow()
    })
    try:
        db.session.commit()
        return jsonify({'message':'Password changed successfully.please login again'}),200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Change password error:{str(e)}')
        return jsonify({'error':'Internal server error'}),500
    


    
    
    
    
    
# ================ HEALTH & TEST ================
@bp.route('/health', methods=['GET'])
@limiter.limit("60 per minute")
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

@bp.route('/test', methods=['GET'])
def test():
    return "Auth blueprint is working!", 200
