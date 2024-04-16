# app/api/user_data.py
# 
# Author: Indrajit Ghosh
# Created On: Apr 01, 2024
# 

from flask import request
from flask_restful import Resource
from app.models.tag import Tag
from app.models.journal_entry import JournalEntry
from app.models.user import User
from app.utils.encryption import decrypt, encrypt
from scripts.utils import convert_str_to_datetime_utc
from app.extensions import db

class ExportDataResource(Resource):
    """
    - GET /api/mindcanvas/export
    """ 
    def _get_decrypted_entry(self, entry:JournalEntry, key):
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
            'tags': [tag.json() for tag in entry.tags]
        }
    
    def get(self):
        # Get the request json data
        data = request.get_json()
        user_private_key = data['private_key']
        user_id = data['user_id']
        user = User.query.get(user_id)

        # Retrieve user's data
        user_data = {
            'user': user.json(),
            'journal_entries': [self._get_decrypted_entry(entry, user_private_key) for entry in user.journal_entries],
            'tags': [tag.json() for tag in user.tags]
        }

        return user_data


class ImportDataResource(Resource):
    """
    - POST /api/mindcanvas/import
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
                _date_created = convert_str_to_datetime_utc(entry_data['date_created'])
                _last_updated = convert_str_to_datetime_utc(entry_data['last_updated'])


                # Create JournalEntry object
                journal_entry = JournalEntry(
                    title=_title,
                    content=_content,
                    locked=entry_data['locked'],
                    favourite=entry_data['favourite'],
                    date_created=_date_created,
                    last_updated=_last_updated,
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
                                color_red=tag_data['color_red'],
                                color_green=tag_data['color_green'],
                                color_blue=tag_data['color_blue'],
                                creator_id=user.id  # Associate with the current user
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
                        color_red=tag_data['color_red'],
                        color_green=tag_data['color_green'],
                        color_blue=tag_data['color_blue'],
                        creator_id=user.id  # Associate with the current user
                    )
                    db.session.add(tag)

            # Commit changes to the database
            db.session.commit()

            return {'message': 'Data imported successfully'}, 200

        except Exception as e:
            # Rollback changes in case of error
            db.session.rollback()
            return {'message': str(e)}, 500
