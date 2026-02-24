
# from datetime import datetime,timedelta

# from app.extensions import db
# import secrets

# class User(db.Model):
#     __tablename__='users'
#     id=db.Column(db.Integer,primary_key=True)
#     username=db.Column(db.String(64),unique=True,nullable=False,index=True)
#     email=db.Column(db.String(120),unique=True,nullable=False,index=True)
#     password_hash=db.Column(db.String(128),nullable=False)
#     is_verified=db.Column(db.Boolean,default=False)
#     is_active=db.Column(db.Boolean,default=True)
#     created_at=db.Column(db.DateTime,default=datetime.utcnow)
#     updated_at=db.Column(db.DateTime,default=datetime.utcnow, onupdate=datetime.utcnow)

#     tokens=db.relationship('Token',backref='user',lazy=True,cascade='all, delete-orphan')
#     login_attempts=db.relationship('LoginAttempt',backref='user',lazy=True)
    
#     def __repr__(self):
#         return f"<User {self.username}>"
#     def to_dict(self):
#         return {
#             'id':self.id,
#             'email':self.email,
#             'is_verified':self.is_verified,
#             'created_at':self.created_at.isoformat() if self.created_at else None,
#             'updated_at':self.updated_at.isoformat() if self.updated_at else None
#         }
# class Token(db.Model):
#     __tablename__='tokens' 
#     id=db.Column(db.String(500),nullable=False,index=True)
#     token=db.Column(db.String(20),nullable=False)
#     token_type=db.Column(db.String(20),nullable=False)
#     expires_at=db.Column(db.DateTime,nullable=False)
#     user_id=db.Column(db.Integer,db.Foreignkey('users.id'),nullable=False)
#     is_used=db.Column(db.Boolean,default=False)
#     revoked_info=db.Column(db.DateTime)
#     device_info=db.Column(db.String(200))
#     ip_address=db.Column(db.DateTime,default=datetime.utcnow)

#     def is_expired(self):
#         return datetime.utcnow() > self.expires_at
#     def is_valid(self):
#         return not self.is_used and not self.is_expired() and not self.revoked_at
# class LoginAttempt(db.Model):
#     __tablename__='login_attempts'
#     id=db.Column(db.Integer,db.ForeignKey('users.id'))
#     user_id=db.Column(db.Integer,db.ForeignKey('users.id'))
#     email=db.Column(db.String(120),nullable=False)
#     ip_address=db.Column(db.String(45),nullable=False)
#     user_agent=db.Column(db.String(200))
#     success=db.Column(db.Boolean,default=False)
#     created_at=db.Column(db.DateTime,default=datetime.utcnow)
#     __table_args_=(
#         db.Index('ix_login_attempts_email_ip','email','ip_address'),
#         db.Index('ix_login_attempts_created_at','created_at'),
#     )

from datetime import datetime, timedelta
from app.extensions import db
import secrets


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)

    is_verified = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tokens = db.relationship('Token', backref='user', lazy=True, cascade='all, delete-orphan')
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Token(db.Model):
    __tablename__ = 'tokens'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), nullable=False, unique=True)
    token_type = db.Column(db.String(20), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    is_used = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    device_info = db.Column(db.String(200))
    ip_address = db.Column(db.String(45))

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def is_valid(self):
        return not self.is_used and not self.is_expired() and not self.revoked_at


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    email = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(200))
    success = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.Index('ix_login_attempts_email_ip', 'email', 'ip_address'),
        db.Index('ix_login_attempts_created_at', 'created_at'),
    )
