from flask import Flask, jsonify
from flask_cors import CORS
from app.config import Config
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Setup logging
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Application startup')
    
    # Initialize extensions
    from app.extensions import db, bcrypt, jwt, mail, migrate, limiter
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # JWT configuration
  ##  from app.auth import jwt_callbacks
  #  jwt_callbacks.setup_jwt_callbacks(jwt)
    
    # Register blueprints
    from app.auth.routes import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    
   # from app.api.routes import bp as api_bp
    #app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    # Error handlers
    register_error_handlers(app)
        # ✅ YEH 4 LINES ADD KAR - Tables automatically ban jayengi
    with app.app_context():
        db.create_all()
        app.logger.info("✅ Database tables created/verified on startup")
    
    # Health check endpoint (global)
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})
    
    return app

def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({'error': 'Method not allowed'}), 405
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f'Server error: {error}')
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': str(e.description)
        }), 429
