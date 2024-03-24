# Models for the app
# 
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
# 

from app.extensions import db
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask_login import UserMixin
from datetime import datetime, timezone
import secrets

from scripts.utils import sha256_hash

# Association Table for many-to-many relationship between JournalEntry and Tag
journal_entry_tag_association = db.Table(
    'journal_entry_tag',
    db.Column('journal_entry_id', db.Integer, db.ForeignKey('journal_entry.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    password_salt = db.Column(db.String(32), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    last_updated = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    # Define a one-to-many relationship with JournalEntry
    journal_entries = db.relationship('JournalEntry', backref='author', lazy=True, cascade="all, delete-orphan")

    # Define a one-to-many relationship with Tag
    tags = db.relationship('Tag', backref='creator', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"MindCanvasUser(username={self.username}, email={self.email}, created_at={self.date_joined} [UTC])"
    
    def set_hashed_password(self, password):
        """Sets the password_hash"""
        # Generate a random salt
        salt = secrets.token_hex(16)
        self.password_salt = salt

        # Combine password and salt, then hash
        password_with_salt = password + salt
        hashed_password = sha256_hash(password_with_salt)
        self.password_hash = hashed_password

    def check_password(self, password):
        # Combine entered password and stored salt, then hash and compare with stored hash
        password_with_salt = password + self.password_salt
        hashed_password = sha256_hash(password_with_salt)
        return hashed_password == self.password_hash

    def avatar(self, size):
        email_hash = sha256_hash(self.email.lower())
        return f"https://gravatar.com/avatar/{email_hash}?d=identicon&s={size}"
    
    def get_reset_password_token(self):
        auth_serializer = URLSafeTimedSerializer(
            secret_key=current_app.config['SECRET_KEY'], salt=current_app.config['SECURITY_PASSWORD_SALT']
        )
        token = auth_serializer.dumps({'id': self.id})
        return token
    
    @staticmethod
    def verify_reset_password_token(token):
        auth_serializer = URLSafeTimedSerializer(
            secret_key=current_app.config['SECRET_KEY'], salt=current_app.config['SECURITY_PASSWORD_SALT']
        )

        try:
            data = auth_serializer.loads(token, max_age=3600)
        except Exception as e:
            return None  # Invalid token
        
        user_id = data.get('id')

        if user_id is None:
            return None  # Invalid token structure
        
        return User.query.get(user_id)
    

class JournalEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    locked = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    last_updated = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    # Define foreign key relationship with User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Define many-to-many relationship with Tag
    tags = db.relationship('Tag', secondary=journal_entry_tag_association, backref=db.backref('journal_entries', lazy='dynamic'))

    def __repr__(self):
        return f"JournalEntry(title={self.title}, date_created={self.date_created} [UTC])"

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    color_red = db.Column(db.Integer, nullable=False)
    color_green = db.Column(db.Integer, nullable=False)
    color_blue = db.Column(db.Integer, nullable=False)

    # Define the foreign key relationship with User
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


    def __repr__(self):
        return f"Tag(name={self.name})"

    def color_rgb(self):
        return f'rgb({self.color_red}, {self.color_green}, {self.color_blue})'
