from datetime import datetime
import uuid
from flask_login import UserMixin
from app import db, bcrypt

class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    permissions = db.Column(db.Integer, default=0)
    
    users = db.relationship('User', backref='role', lazy='dynamic')
    
    def __repr__(self):
        return f'<Role {self.name}>'
    
    @staticmethod
    def insert_roles():
        roles = {
            'user': 0x01,      # 1: accès de base
            'moderator': 0x07, # 7: accès modéré (1 + 2 + 4)
            'admin': 0xFF      # 255: tous les accès
        }
        for role_name, permissions in roles.items():
            role = Role.query.filter_by(name=role_name).first()
            if role is None:
                role = Role(name=role_name, permissions=permissions)
            else:
                role.permissions = permissions
            db.session.add(role)
        db.session.commit()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    
    # champs de sécurité et de statut
    confirmed = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # champs de journalisation de sécurité
    login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            self.role = Role.query.filter_by(name='user').first()
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def has_permission(self, permission):
        return self.role is not None and (self.role.permissions & permission) == permission
    
    def is_administrator(self):
        return self.has_permission(0xff)
    
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
    
    def __repr__(self):
        return f'<User {self.username}>'
