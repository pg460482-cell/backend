from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.api import bp
from app.models import User, Token
from datetime import datetime

# =========================
# GET CURRENT USER PROFILE
# =========================
@bp.route('/users/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(user.to_dict()), 200


# =========================
# UPDATE CURRENT USER
# =========================
@bp.route('/users/me', methods=['PUT'])
@jwt_required()
def update_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # ---- Username update ----
    if 'username' in data and data['username'] != user.username:
        if not data['username'].strip():
            return jsonify({'error': 'Username cannot be empty'}), 400

        existing = User.query.filter_by(username=data['username']).first()
        if existing:
            return jsonify({'error': 'Username already taken'}), 409

        user.username = data['username']

    # ---- Email update ----
    if 'email' in data and data['email'] != user.email:
        if not data['email'].strip():
            return jsonify({'error': 'Email cannot be empty'}), 400

        existing = User.query.filter_by(email=data['email']).first()
        if existing:
            return jsonify({'error': 'Email already registered'}), 409

        user.email = data['email']
        user.is_verified = False

    db.session.commit()

    return jsonify({
        'message': 'Profile updated successfully',
        'user': user.to_dict()
    }), 200


# =========================
# GET ACTIVE SESSIONS
# =========================
@bp.route('/users/me/sessions', methods=['GET'])
@jwt_required()
def get_user_session():
    user_id = get_jwt_identity()

    active_sessions = Token.query.filter(
        Token.user_id == user_id,
        Token.token_type == 'refresh',
        Token.is_used == False,
        Token.expires_at > datetime.utcnow()
    ).all()

    sessions = []
    for session in active_sessions:
        sessions.append({
            'id': session.id,
            'device': session.device_info,
            'ip_address': session.ip_address,
            'created_at': session.created_at.isoformat(),
            'expires_at': session.expires_at.isoformat()
        })

    return jsonify({'sessions': sessions}), 200


# =========================
# REVOKE A SESSION
# =========================
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

    session.is_used = True
    session.revoked_at = datetime.utcnow()
    db.session.commit()

    return jsonify({'message': 'Session revoked successfully'}), 200


# =========================
# TEST API
# =========================
@bp.route('/test', methods=['GET'])
def test():
    return jsonify({'message': 'API is working'}), 200



