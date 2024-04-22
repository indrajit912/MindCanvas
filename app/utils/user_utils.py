"""Utility functions for User operations."""
# Author: Indrajit Ghosh
# Created On: Apr 18, 2024

from app.extensions import db
from app.models.user import User
from app.models.journal_entry import JournalEntry
from app.models.tag import Tag
from scripts.utils import utcnow
from app.utils.encryption import decrypt, encrypt
from scripts.utils import convert_str_to_datetime_utc, sha256_hash

from werkzeug.exceptions import HTTPException
from sqlalchemy.exc import SQLAlchemyError
from cryptography.fernet import Fernet

import logging

logger = logging.getLogger(__name__)

def create_new_user(fullname:str, email:str, username:str, password:str, email_verified:bool=None):
    """Create a new user.

    Args:
        fullname (str): The fullname of the user.
        email (str): The email address of the user.
        username (str): The username of the user.
        password (str): The password of the user.
        email_verified (bool, optional): Indicates whether the user's email is verified.

    Returns:
        tuple: A tuple containing a status code and a dictionary representation of the created user.

    """
    try:
        # Check if the user already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            if existing_user.email == email:
                return 400, {'message': 'email_taken'}
            else:
                return 400, {'message': 'username_taken'}

        # Create a new user
        new_user = User(
            fullname=fullname,
            email=email,
            username=username,
        )
        new_user.set_hashed_password(password)

        # Set private key
        user_key = Fernet.generate_key()
        new_user.set_encrypted_private_key(private_key=user_key, password=password)

        if email_verified is not None:
            new_user.email_verified = email_verified

        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()

        return 200, new_user.json()
    except Exception as e:
        db.session.rollback()
        error_message = f"An error occurred while creating the user: {e}"
        return 500, {'error': error_message}
    

def update_user(user_id, data: dict):
    try:
        # Retrieve the user to update
        user = User.query.get_or_404(user_id)

        # Check if the email or username is already in use by another user
        if 'email' in data or 'username' in data:
            existing_user = User.query.filter(
                (User.id != user_id) &
                ((User.username == data.get('username')) | (User.email == data.get('email')))
            ).first()
            if existing_user:
                if existing_user.email == data.get('email'):
                    return 400, {'message': 'email_taken'}
                else:
                    return 400, {'message': 'username_taken'}

        # Update the user attributes if provided in the request
        if 'fullname' in data:
            user.fullname = data.get('fullname')
        if 'email' in data:
            user.email = data.get('email')
            user.email_verified = False
        if 'username' in data:
            user.username = data.get('username')
        if 'is_admin' in data:
            user.is_admin = data.get('is_admin')
        if 'email_verified' in data:
            user.email_verified = data.get('email_verified')
        if 'password' in data:
            return 400, {"message": "password-not-accepted"}

        # Change last updated info
        user.last_updated = utcnow()

        # Commit changes to the database
        db.session.commit()

        return 200, {'message': 'User updated successfully'}
    
    except SQLAlchemyError as e:
        # Rollback changes if an exception occurs
        db.session.rollback()
        return 500, {'message': 'An error occurred while updating user data'}


def update_user_last_seen(user_id):
    # Retrieve the user from the database using user_id
    user = User.query.get_or_404(user_id)
    
    # Update the last_seen attribute of the user
    user.last_seen = utcnow()
    
    # Commit the changes to the database
    db.session.commit()
    
    return 200, {'message': 'last_seen attribute updated successfully for "{user.username}"'}


def delete_user_from_db(user_id):
    try:
        # Retrieve the user to delete
        user = User.query.get_or_404(user_id)

        # Delete the user from the database
        db.session.delete(user)
        db.session.commit()

        return 200, {'message': 'User deleted successfully'}
    
    except SQLAlchemyError:
        # Rollback changes if an exception occurs
        db.session.rollback()
        return 500, {'message': 'An error occurred while deleting user'}


def change_user_password(user_id:int, new_password:str, private_key:str):
    """Change user's password and update encrypted private key.

    Args:
        user_id (int): The ID of the user whose password is being changed.
        new_password (str): The new password for the user.
        private_key (str): The encrypted private key for the user.

    Returns:
        tuple: A tuple containing a status code and a dictionary with a message indicating the success of the operation.

    Raises:
        HTTPException: If the user with the specified ID is not found.

    """
    try:
        # Retrieve the user from the database using user_id
        user = User.query.get_or_404(user_id)
        
        # Set the new password hash
        user.set_hashed_password(new_password)

        # Set user's encrypted private key with the new password
        user.set_encrypted_private_key(private_key=private_key, password=new_password)
        
        # Commit the changes to the database
        db.session.commit()
        
        return 200, {'message': 'Password changed successfully.'}
    except HTTPException as e:
        # Catch and re-raise HTTPExceptions
        raise e
    except Exception as e:
        # Catch other exceptions and return an appropriate status code
        return 500, {'message': 'An error occurred while changing the password.'}


def export_user_data(user_id:int, private_key:str):
    """Export user data.

    Args:
        user_id (int): The ID of the user whose data is being exported.
        private_key (str): The private key of the user for decryption.

    Returns:
        dict: A dictionary containing the user's data including journal entries and tags.

    """
    # Retrieve user from the database using user_id
    user = User.query.get(user_id)

    # Retrieve user's data
    user_data = {
        'user': user.json(),
        'journal_entries': [get_decrypted_entry(entry, private_key) for entry in user.journal_entries],
        'tags': [
            {
                "name": decrypt(tag.name, private_key),
                'name_hash': tag.name_hash,
                'description': tag.description,
                'color_red': tag.color_red,
                'color_green': tag.color_green,
                'color_blue': tag.color_blue,
                'color_hex': tag.color_hex(), 
                'creator_id': tag.creator_id,
                'date_created': Tag.format_datetime_to_str(tag.date_created),
                'last_updated': Tag.format_datetime_to_str(tag.last_updated)
            } 
            for tag in user.tags
        ]
    }

    return user_data

def get_decrypted_entry(entry:JournalEntry, key:str):
    """Decrypt a journal entry.

    Args:
        entry (JournalEntry): The journal entry to decrypt.
        key (str): The private key for decryption.

    Returns:
        dict: A dictionary containing the decrypted journal entry.

    """
    decrypted_title = decrypt(entry.title, key)
    decrypted_content = decrypt(entry.content, key)

    return {
        'id': entry.id,
        'uuid': entry.uuid,
        'title': decrypted_title,
        'content': decrypted_content,
        'locked': entry.locked,
        'favourite': entry.favourite,
        'date_created': JournalEntry.format_datetime_to_str(entry.date_created),
        'last_updated': JournalEntry.format_datetime_to_str(entry.last_updated),
        'author_id': entry.author_id,
        'tags': [
            {
                "name": decrypt(tag.name, key),
                'name_hash': tag.name_hash,
                'description': tag.description,
                'color_red': tag.color_red,
                'color_green': tag.color_green,
                'color_blue': tag.color_blue,
                'color_hex': tag.color_hex(), 
                'creator_id': tag.creator_id,
                'date_created': Tag.format_datetime_to_str(tag.date_created),
                'last_updated': Tag.format_datetime_to_str(tag.last_updated)
            }
            for tag in entry.tags
        ] # TODO: decrypt the tag.name only!
    }


def import_user_data(data: dict):
    """
    Import journal entries and tags from JSON data and associate them with the user.

    Args:
        data (dict): JSON data containing journal entries and tags.

    Returns:
        tuple: A tuple containing an HTTP status code and a dictionary with a message indicating the success or failure of the import operation.

    """
    try:
        with db.session.begin_nested():
            user_private_key = data.get('private_key')
            user_id = data.get('user_id')
            user = User.query.get(user_id)

            if not user_private_key:
                return 400, {"message": "User's private key required!"}
            
            # Check if 'journal_entries' and 'tags' are present in the JSON
            if 'journal_entries' not in data or 'tags' not in data:
                return 400, {'message': 'Invalid JSON format'}
            
            # Import Tags
            for tag_data in data['tags']:
                tag = Tag.query.filter_by(name_hash=sha256_hash(tag_data['name']), creator_id=user.id).first()
                if not tag:
                    tag = _create_tag(tag_data, user, user_private_key)
                    db.session.add(tag)

            # Import Journal Entries
            for entry_data in data['journal_entries']:
                journal_entry = _create_journal_entry(entry_data, user, user_private_key)
                db.session.add(journal_entry)

        return 200, {'message': 'Data imported successfully'}

    except SQLAlchemyError as e:
        db.session.rollback()
        return 500, {'message': str(e)}
    except Exception as e:
        return 500, {'message': str(e)}

def _create_tag(tag_data, user, user_private_key):
    """
    Create a tag from tag data.

    Args:
        tag_data (dict): Tag data.
        user (User): User object.
        user_private_key (str): User's private key.

    Returns:
        Tag: Created Tag object.
    """
    tag = Tag(
        name=encrypt(tag_data['name'], user_private_key),
        color_red=tag_data['color_red'],
        color_green=tag_data['color_green'],
        color_blue=tag_data['color_blue'],
        date_created=convert_str_to_datetime_utc(tag_data['date_created']),
        last_updated=convert_str_to_datetime_utc(tag_data['last_updated']),
        creator_id=user.id
    )
    tag.set_name_hash(tag_data['name'])
    return tag

def _create_journal_entry(entry_data, user, user_private_key):
    """
    Create a journal entry from entry data.

    Args:
        entry_data (dict): Journal entry data.
        user (User): User object.
        user_private_key (str): User's private key.

    Returns:
        JournalEntry: Created JournalEntry object.
    """
    _title = encrypt(entry_data['title'], user_private_key)
    _content = encrypt(entry_data['content'], user_private_key)
    _date_created = convert_str_to_datetime_utc(entry_data['date_created'])
    _last_updated = convert_str_to_datetime_utc(entry_data['last_updated'])

    journal_entry = JournalEntry(
        title=_title,
        content=_content,
        locked=entry_data['locked'],
        favourite=entry_data['favourite'],
        date_created=_date_created,
        last_updated=_last_updated,
        author=user
    )
    db.session.add(journal_entry)

    # Add tags to the journal entry
    if 'tags' in entry_data:
        for tag_data in entry_data['tags']:
            tag = Tag.query.filter_by(name_hash=sha256_hash(tag_data['name']), creator_id=user.id).first()
            if not tag:
                tag = _create_tag(tag_data, user, user_private_key)
                db.session.add(tag)
            journal_entry.tags.append(tag)

    return journal_entry
