# Models for the app
# 
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
# 

from app.extensions import db
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask_login import UserMixin
import secrets
import uuid
from scripts.utils import sha256_hash, utcnow
from app.models.tag import Tag


class User(db.Model, UserMixin):
    """
    User model for storing user related details.

    Attributes:
        id (int): The primary key of the user.
        uuid (str): Unique identifier for the user.
        username (str): User's username.
        fullname (str): Full name of the user.
        email (str): User's email address.
        password_hash (str): Hashed password of the user.
        password_salt (str): Salt used for hashing the password.
        is_admin (bool): Indicates if the user is an administrator.
        date_joined (datetime): Date and time when the user joined.
        last_updated (datetime): Date and time when the user profile was last updated.
        journal_entries (Relationship): One-to-many relationship with JournalEntry model.
        tags (Relationship): One-to-many relationship with Tag model.

    Methods:
        __repr__: Representation of the User object.
        set_hashed_password: Set hashed password for the user.
        check_password: Check if the provided password matches the user's hashed password.
        avatar: Generate Gravatar URL for the user's avatar.
        get_reset_password_token: Generate a reset password token for the user.
        json: Return dictionary representation of the user.
        verify_reset_password_token: Verify the reset password token.
    """

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: uuid.uuid4().hex)
    username = db.Column(db.String(100), unique=True, nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    password_salt = db.Column(db.String(32), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, default=utcnow)
    last_updated = db.Column(db.DateTime, default=utcnow)

    journal_entries = db.relationship('JournalEntry', backref='author', lazy=True, cascade="all, delete-orphan")
    tags = db.relationship('Tag', backref='creator', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        """Representation of the User object."""
        return f"User(username={self.username}, email={self.email}, created_at={self.date_joined})"
    
    def set_hashed_password(self, password):
        """
        Set hashed password for the user.

        Args:
            password (str): Plain text password to be hashed.
        """
        salt = secrets.token_hex(16)
        self.password_salt = salt

        password_with_salt = password + salt
        hashed_password = sha256_hash(password_with_salt)
        self.password_hash = hashed_password

    def check_password(self, password):
        """
        Check if the provided password matches the user's hashed password.

        Args:
            password (str): Plain text password to be checked.

        Returns:
            bool: True if password matches, False otherwise.
        """
        password_with_salt = password + self.password_salt
        hashed_password = sha256_hash(password_with_salt)
        return hashed_password == self.password_hash

    def avatar(self, size):
        """
        Generate Gravatar URL for the user's avatar.

        Args:
            size (int): Size of the avatar image.

        Returns:
            str: URL of the user's Gravatar avatar.
        """
        email_hash = sha256_hash(self.email.lower())
        return f"https://gravatar.com/avatar/{email_hash}?d=identicon&s={size}"
    
    def get_reset_password_token(self):
        """
        Generate a reset password token for the user.

        Returns:
            str: Reset password token.
        """
        auth_serializer = URLSafeTimedSerializer(
            secret_key=current_app.config['SECRET_KEY'], salt=current_app.config['SECURITY_PASSWORD_SALT']
        )
        token = auth_serializer.dumps({'id': self.id})
        return token
    
    def json(self):
        """
        Return dictionary representation of the user.

        Returns:
            dict: Dictionary containing user details.
        """
        return {
            'id': self.id,
            'uuid': self.uuid,
            'username': self.username,
            'fullname': self.fullname,
            'email': self.email,
            'is_admin': self.is_admin,
            'date_joined': User.format_datetime_to_str(self.date_joined),
            'last_updated': User.format_datetime_to_str(self.last_updated)
        }
    
    @staticmethod
    def format_datetime_to_str(dt):
        """
        Formats a datetime object to the UTC string format: "Wed, 27 Mar 2024 07:10:10 UTC".

        Parameters:
            dt (datetime): A datetime object to be formatted.

        Returns:
            str: A string representing the datetime object in the UTC format.
        """
        return dt.strftime('%a, %d %b %Y %H:%M:%S UTC')

    
    @staticmethod
    def verify_reset_password_token(token):
        """
        Verify the reset password token.

        Args:
            token (str): Reset password token.

        Returns:
            User or None: User object if token is valid, None otherwise.
        """
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
    
