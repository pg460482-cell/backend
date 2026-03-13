import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # App
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    FLASK_ENV  = os.environ.get('FLASK_ENV', 'production')

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # ✅ SSL fix
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # JWT
    JWT_SECRET_KEY            = os.environ.get('JWT_SECRET_KEY', 'dev-jwt-secret')
    JWT_ACCESS_TOKEN_EXPIRES  = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_TOKEN_LOCATION        = ['headers']
    JWT_HEADER_NAME           = 'Authorization'
    JWT_HEADER_TYPE           = 'Bearer'

    # Email
    MAIL_SERVER         = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT           = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS        = True
    MAIL_USE_SSL        = False
    MAIL_USERNAME       = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD       = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')

    # Rate Limiting
    RATELIMIT_DEFAULT     = "200 per day, 50 per hour"
    RATELIMIT_STORAGE_URI = os.environ.get('REDIS_URL', 'memory://')
    RATELIMIT_STRATEGY    = 'fixed-window'

    # Security
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT', 'dev-salt')
    BCRYPT_LOG_ROUNDS      = 12

    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000').split(',')

    # API
    API_VERSION     = '1.0'
    API_TITLE       = 'Authentication API'
    API_DESCRIPTION = 'RESTful Authentication API'

    # ✅ Base init_app
    @classmethod
    def init_app(cls, app):
        pass


class DevelopmentConfig(Config):
    DEBUG                    = True
    SQLALCHEMY_ECHO          = True
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=1)


class TestingConfig(Config):
    TESTING                 = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED        = False


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

    @classmethod
    def init_app(cls, app):
        super().init_app(app)
        required_vars = ['SECRET_KEY', 'DATABASE_URL', 'JWT_SECRET_KEY']
        missing = [var for var in required_vars if not os.environ.get(var)]
        if missing:
            raise ValueError(f"Missing required environment variables: {missing}")


config = {
    'development': DevelopmentConfig,
    'testing':     TestingConfig,
    'production':  ProductionConfig,
    'default':     DevelopmentConfig
}
