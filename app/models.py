from datetime import datetime, timezone
from app.extensions import db


class User(db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_verified   = db.Column(db.Boolean, default=False)   # Fix: True → False
    is_active     = db.Column(db.Boolean, default=True)

    # Fix: lambda wrap + timezone aware
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    tokens = db.relationship(
        'Token',
        backref='user',
        lazy=True,
        cascade='all, delete-orphan'
    )
    login_attempts = db.relationship(
        'LoginAttempt',
        backref='user',
        lazy=True,
        cascade='all, delete-orphan'    # Fix: cascade missing tha
    )

    def to_dict(self):
        return {
            'id':          self.id,
            'username':    self.username,                   # Fix: missing tha
            'email':       self.email,
            'is_verified': self.is_verified,
            'created_at':  self.created_at.isoformat() if self.created_at else None,
            'updated_at':  self.updated_at.isoformat() if self.updated_at else None,
        }


class Token(db.Model):
    __tablename__ = 'tokens'

    id         = db.Column(db.Integer, primary_key=True)
    token      = db.Column(db.String(500), nullable=False, unique=True)
    token_type = db.Column(db.String(20), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_used    = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime(timezone=True))

    # Fix: lambda wrap
    created_at  = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    expires_at  = db.Column(db.DateTime(timezone=True), nullable=False)
    device_info = db.Column(db.String(200))
    ip_address  = db.Column(db.String(45))

    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at  # Fix: utcnow() deprecated

    def is_valid(self):
        return (
            not self.is_used
            and not self.is_expired()
            and self.revoked_at is None                     # Fix: explicit None check
        )


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'))
    email      = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(200))
    success    = db.Column(db.Boolean, default=False)

    # Fix: lambda wrap
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        db.Index('ix_login_attempts_email_ip', 'email', 'ip_address'),
        db.Index('ix_login_attempts_created_at', 'created_at'),
    )
