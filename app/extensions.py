from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import jsonify

db      = SQLAlchemy()
bcrypt  = Bcrypt()
jwt     = JWTManager()
mail    = Mail()
migrate = Migrate()

# Fix: default_limits hata — config.py ke RATELIMIT_DEFAULT se automatically aata hai
limiter = Limiter(
    key_func=get_remote_address,
)


# ================= JWT CALLBACKS =================

@jwt.user_identity_loader
def user_identity_lookup(identity):
    """User object ya user id dono handle karo"""
    if hasattr(identity, 'id'):
        return str(identity.id)
    return str(identity)


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """JWT se user fetch karo"""
    from app.models import User

    identity = jwt_data["sub"]
    user     = db.session.get(User, int(identity))

    if user is None:
        return None

    if hasattr(user, 'is_active') and not user.is_active:
        return None

    return user


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'error':   'token_expired',
        'message': 'Token has expired, please refresh your token'
    }), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'error':   'invalid_token',
        'message': 'Provided token is invalid'
    }), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'error':   'authorization_required',
        'message': 'No token provided, please login'
    }), 401


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'error':   'token_revoked',
        'message': 'Token has been revoked, please login again'
    }), 401


@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
    return jsonify({
        'error':   'fresh_token_required',
        'message': 'Please login again to perform this action'
    }), 401
