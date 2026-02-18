from functools import wraps
from flask import request, jsonify
from app.extensions import limiter

def validate_schema(schema):
    """Validate request data against schema"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = request.get_json(silent=True)
            if data is None:
                return jsonify({'error': 'Invalid JSON'}), 400
            
            errors = schema.validate(data)
            if errors:
                return jsonify({'error': 'Validation failed', 'details': errors}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_json(f):
    """Require JSON content type"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_by_ip(limit, period):
    """Custom rate limit by IP"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return limiter.limit(f"{limit}/{period}seconds", key_func=lambda: request.remote_addr)(f)(*args, **kwargs)
        return decorated_function
    return decorator