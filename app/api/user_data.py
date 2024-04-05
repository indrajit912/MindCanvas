# app/api/user_data.py
# 
# Author: Indrajit Ghosh
# Created On: Apr 01, 2024
# 

from flask import request, session
from flask_restful import Resource
from app.models.tag import Tag
from app.models.journal_entry import JournalEntry
from app.models.user import User
from app.utils.encryption import decrypt, encrypt
from app.extensions import db
from flask_login import current_user

class UserDataResource(Resource):
    def _get_decrypted_entry(self, entry:JournalEntry):
        key = session['current_user_private_key']
        decrypted_title = decrypt(entry.title, key)
        decrypted_content = decrypt(entry.content, key)

        return {
            'id': entry.id,
            'uuid': entry.uuid,
            'title': decrypted_title,
            'content': decrypted_content,
            'locked': entry.locked,
            'date_created': JournalEntry.format_datetime_to_str(entry.date_created),
            'last_updated': JournalEntry.format_datetime_to_str(entry.last_updated),
            'author_id': entry.author_id,
            'tags': [tag.json() for tag in entry.tags]
        }
    
    def get(self):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            return {'message': 'User is not authenticated'}, 401

        # Retrieve user's data
        user_data = {
            'user': current_user.json(),
            'journal_entries': [self._get_decrypted_entry(entry) for entry in current_user.journal_entries],
            'tags': [tag.json() for tag in current_user.tags]
        }

        return user_data


class ImportDataResource(Resource):
    """
    - POST /api/mindcanvas/data/import
        json_body should have `private_key` and `user_id` included
    """
    def post(self):
        # TODO: use user token
        try:
            data = request.get_json()
            user_private_key = data['private_key']
            user_id = data['user_id']
            user = User.query.get(user_id)

            if not user_private_key:
                return {"message": "User's private key required!"}, 401
            
            # Check if 'journal_entries' and 'tags' are present in the JSON
            if 'journal_entries' not in data or 'tags' not in data:
                return {'message': 'Invalid JSON format'}, 400

            # Import Journal Entries
            for entry_data in data['journal_entries']:
                # Encrypt the JournalEntry title and content
                _title = encrypt(entry_data['title'], user_private_key)
                _content = encrypt(entry_data['content'], user_private_key)


                # Create JournalEntry object
                journal_entry = JournalEntry(
                    title=_title,
                    content=_content,
                    locked=entry_data['locked'],
                    author=user  # Associate with the current user
                )

                db.session.add(journal_entry)  # Add the JournalEntry to the session

                # Commit changes to the database before associating with tags
                db.session.commit()

                # Add tags to the journal entry
                if 'tags' in entry_data:
                    for tag_data in entry_data['tags']:
                        tag = Tag.query.filter_by(name=tag_data['name']).first()
                        if not tag:
                            # Create new tag if not exists
                            tag = Tag(
                                name=tag_data['name'],
                                creator=user  # Associate with the current user
                            )
                        journal_entry.tags.append(tag)

                db.session.add(journal_entry)

            # Import Tags
            for tag_data in data['tags']:
                tag = Tag.query.filter_by(name=tag_data['name']).first()
                if not tag:
                    # Create new tag if not exists
                    tag = Tag(
                        name=tag_data['name'],
                        creator=user  # Associate with the current user
                    )
                    db.session.add(tag)

            # Commit changes to the database
            db.session.commit()

            return {'message': 'Data imported successfully'}, 200

        except Exception as e:
            # Rollback changes in case of error
            db.session.rollback()
            return {'message': str(e)}, 500
