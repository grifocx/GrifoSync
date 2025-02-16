
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    backup_jobs = db.relationship('BackupJob', backref='user', lazy=True)
    cloud_credentials = db.relationship('CloudCredentials', backref='user', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CloudCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    icloud_username = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def icloud_password(self):
        return os.getenv(f'ICLOUD_PWD_{self.user_id}')

    @property
    def aws_access_key(self):
        return os.getenv(f'AWS_KEY_{self.user_id}')

    @property
    def aws_secret_key(self):
        return os.getenv(f'AWS_SECRET_{self.user_id}')

    @property
    def s3_bucket(self):
        return os.getenv(f'S3_BUCKET_{self.user_id}')
