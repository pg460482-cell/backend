from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.api import bp
from app.models import User, Token
from datetime import datetime, timezone
import re


def get_real_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def sanitize_input(text):
    if text:
        return re.sub(r'[<>&\']', '', text)
    return text


def validate_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


# ================= GET CURRENT USER =================

@bp.route('/users/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user = db.session.get(User, get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user.to_dict()), 200


# ================= UPDATE CURRENT USER =================

@bp.route('/users/me', methods=['PUT'])
@jwt_required()
def update_current_user():
    user = db.session.get(User, get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    if 'username' in data and data['username'] != user.username:
        new_username = sanitize_input(data['username'].strip())

        if not new_username:
            return jsonify({'error': 'Username cannot be empty'}), 400
        if len(new_username) < 3 or len(new_username) > 20:
            return jsonify({'error': 'Username must be between 3 and 20 characters'}), 400
        if not re.match(r'^[A-Za-z][A-Za-z0-9_.]*$', new_username):
            return jsonify({'error': 'Username must start with a letter'}), 400

        existing = User.query.filter_by(username=new_username).first()
        if existing:
            return jsonify({'error': 'Username already taken'}), 409

        user.username = new_username

    if 'email' in data and data['email'] != user.email:
        new_email = data['email'].strip().lower()

        if not new_email:
            return jsonify({'error': 'Email cannot be empty'}), 400
        if not validate_email_format(new_email):
            return jsonify({'error': 'Invalid email format'}), 400

        existing = User.query.filter_by(email=new_email).first()
        if existing:
            return jsonify({'error': 'Email already registered'}), 409

        user.email       = new_email
        user.is_verified = False

    try:
        db.session.commit()
        return jsonify({
            'message': 'Profile updated successfully',
            'user':    user.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500


# ================= GET ACTIVE SESSIONS =================

@bp.route('/users/me/sessions', methods=['GET'])
@jwt_required()
def get_user_sessions():
    user_id = get_jwt_identity()

    active_sessions = Token.query.filter(
        Token.user_id    == user_id,
        Token.token_type == 'refresh',
        Token.is_used    == False,
        Token.expires_at > datetime.now(timezone.utc)
    ).all()

    sessions = [
        {
            'id':         s.id,
            'device':     s.device_info,
            'ip_address': s.ip_address,
            'created_at': s.created_at.isoformat() if s.created_at else None,
            'expires_at': s.expires_at.isoformat() if s.expires_at else None,
        }
        for s in active_sessions
    ]

    return jsonify({'sessions': sessions}), 200


# ================= REVOKE SESSION =================

@bp.route('/users/me/sessions/<int:session_id>', methods=['DELETE'])
@jwt_required()
def revoke_session(session_id):
    user_id = get_jwt_identity()

    session = Token.query.filter_by(
        id=session_id,
        user_id=user_id,
        token_type='refresh'
    ).first()

    if not session:
        return jsonify({'error': 'Session not found'}), 404

    if session.is_used:
        return jsonify({'error': 'Session already revoked'}), 400

    session.is_used    = True
    session.revoked_at = datetime.now(timezone.utc)

    try:
        db.session.commit()
        return jsonify({'message': 'Session revoked successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500


# ================= TEST =================

@bp.route('/test', methods=['GET'])
def test():
    from flask import current_app
    if not current_app.config.get('DEBUG'):
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'message': 'API is working'}), 200
