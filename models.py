from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64
import os

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    backup_jobs = db.relationship('BackupJob', backref='user', lazy=True)
    credentials = db.relationship('CredentialVault', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class BackupJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    total_files = db.Column(db.Integer, default=0)
    processed_files = db.Column(db.Integer, default=0)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    error_message = db.Column(db.Text)

class CredentialVault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    credential_type = db.Column(db.String(20), nullable=False)  # 'icloud' or 'aws'
    encrypted_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_user_credential_type', 'user_id', 'credential_type', unique=True),
    )

    @staticmethod
    def _get_key():
        key = os.environ.get('CREDENTIAL_ENCRYPTION_KEY')
        if not key:
            key = Fernet.generate_key()
            os.environ['CREDENTIAL_ENCRYPTION_KEY'] = key.decode()
        return base64.b64decode(key if isinstance(key, bytes) else key.encode())

    def encrypt_credentials(self, credentials_dict):
        f = Fernet(self._get_key())
        encrypted_data = f.encrypt(str(credentials_dict).encode())
        self.encrypted_data = encrypted_data.decode()

    def decrypt_credentials(self):
        f = Fernet(self._get_key())
        decrypted_data = f.decrypt(self.encrypted_data.encode())
        return eval(decrypted_data.decode())