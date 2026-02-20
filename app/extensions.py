# from flask_sqlalchemy import SQLAlchemy
# from flask_bcrypt import Bcrypt
# from flask_jwt_extended import JWTManager
# from flask_mail import Mail
# from flask_migrate import Migrate
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address

# db=SQLAlchemy()
# bcrypt=Bcrypt()
# jwt=JWTManager()
# mail=Mail()
# migrate=Migrate()
# limiter=Limiter(
#     key_func=get_remote_address,
#     default_limits=["200 per day","50 per hour"]
# )

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import jsonify

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()
mail = Mail()
migrate = Migrate()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ================= JWT CALLBACKS =================
@jwt.user_identity_loader
def user_identity_lookup(identity):
    """Handle both user object and user id"""
    if hasattr(identity, 'id'):  # Agar object hai to
        return str(identity.id)
    return str(identity)  # Agar integer hai to (jaise user.id)

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """JWT se user fetch karo"""
    from app.models import User
    identity = jwt_data["sub"]
    return User.query.get(int(identity))

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    """Token expire ho gaya"""
    return jsonify({
        'error': 'Token has expired',
        'message': 'Please refresh your token'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    """Invalid token"""
    return jsonify({
        'error': 'Invalid token',
        'message': 'Please provide a valid token'
    }), 422

@jwt.unauthorized_loader
def missing_token_callback(error):
    """Token missing"""
    return jsonify({
        'error': 'Authorization required',
        'message': 'Please provide a valid token'
    }), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    """Token revoke ho gaya"""
    return jsonify({
        'error': 'Token has been revoked',
        'message': 'Please login again'
    }), 401
