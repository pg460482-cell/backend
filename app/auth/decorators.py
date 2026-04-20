from functools import wraps
from flask import request, jsonify
from flask_limiter import Limiter
from app.extensions import limiter
import re


def get_real_ip():
    """Proxy ke peeche bhi real IP milegi"""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def validate_schema(schema_class):
    """Validate request data against a Marshmallow schema"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 415

            data = request.get_json(silent=True)
            if data is None:
                return jsonify({'error': 'Invalid or empty JSON body'}), 400

            schema = schema_class() if isinstance(schema_class, type) else schema_class
            errors = schema.validate(data)
            if errors:
                return jsonify({
                    'error':   'Validation failed',
                    'details': errors
                }), 422

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_json(f):
    """Require JSON Content-Type"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        return f(*args, **kwargs)
    return decorated_function


def rate_limit_by_ip(limit_count, period_seconds):
    """
    Custom rate limit by real IP address.
    Usage: @rate_limit_by_ip(5, 60) → 5 requests per 60 seconds
    """
    def decorator(f):
        limited = limiter.limit(
            f"{limit_count} per {period_seconds} seconds",
            key_func=get_real_ip
        )(f)

        @wraps(f)
        def decorated_function(*args, **kwargs):
            return limited(*args, **kwargs)
        return decorated_function
    return decorator
