# app/api/db_resources.py
# 
# Author: Indrajit Ghosh
# Created On: Apr 19, 2024
# 
from flask_restful import Resource, reqparse
from app.models.user import User
from app.models.journal_entry import JournalEntry
from app.models.tag import Tag
from app.utils.decorators import token_required
from app.extensions import db
from scripts.utils import convert_str_to_datetime_utc
import logging

logger = logging.getLogger(__name__)


class ExportDBResource(Resource):
    @token_required
    def get(self):
        # Query all users
        users = User.query.filter(User.username != 'demo').all()
        data = {"data": []}

        for user in users:
            user_data = {}
            
            # Create the user data
            user_data['user'] = {
                "username": user.username,
                "fullname": user.fullname,
                "email": user.email,
                "is_admin": user.is_admin,
                "date_joined": User.format_datetime_to_str(user.date_joined),
                "last_updated": User.format_datetime_to_str(user.last_updated),
                "last_seen": User.format_datetime_to_str(user.last_seen),
                "email_verified": user.email_verified,
                "password_hash": user.password_hash,
                "password_salt": user.password_salt,
                "encrypted_private_key": user.encrypted_private_key.decode(),
                "derived_key_hash": user.derived_key_hash
            }

            # Get all tags of this user
            user_data['tags'] = [
                {
                    "name": tag.name,
                    "description": tag.description,
                    "color_red": tag.color_red,
                    "color_green": tag.color_green,
                    "color_blue": tag.color_blue,
                    "date_created": Tag.format_datetime_to_str(tag.date_created),
                    "last_updated": Tag.format_datetime_to_str(tag.last_updated)
                }
                for tag in Tag.query.filter(Tag.creator_id == user.id).all()
            ]
            
            # Get all journal_entries of this user
            user_data['journal_entries'] = [
                {
                    "title": entry.title,
                    "content": entry.content,
                    "locked": entry.locked,
                    "favourite": entry.favourite,
                    "date_created": JournalEntry.format_datetime_to_str(entry.date_created),
                    "last_updated": JournalEntry.format_datetime_to_str(entry.last_updated),
                    "tags": [tag.name for tag in entry.tags]
                }
                for entry in JournalEntry.query.filter(JournalEntry.author_id == user.id).all()
            ]

            # Append the user data
            data['data'].append(user_data)
        
        return data, 200


class ImportDBResource(Resource):
    def post(self):
        try:
            # Drop all data from tables
            # First, identify the user with the username 'demo'
            demo_user = User.query.filter_by(username='demo').first()
            
            # Then, delete all users except the 'demo' user
            db.session.query(User).filter(User.id != demo_user.id).delete()
            db.session.query(Tag).delete()
            db.session.query(JournalEntry).delete()
            db.session.commit()
            
            parser = reqparse.RequestParser()
            parser.add_argument('data', type=list, location='json', required=True, help='Data is required')
            args = parser.parse_args()
            data = args['data']

            for item in data:
                user_data = item['user']
                user = User(
                    username=user_data['username'],
                    fullname=user_data['fullname'],
                    email=user_data['email'],
                    is_admin=user_data['is_admin'],
                    date_joined=convert_str_to_datetime_utc(user_data['date_joined']),
                    last_updated=convert_str_to_datetime_utc(user_data['last_updated']),
                    last_seen=convert_str_to_datetime_utc(user_data['last_seen']),
                    email_verified=user_data['email_verified'],
                    password_hash=user_data['password_hash'],
                    password_salt=user_data['password_salt'],
                    encrypted_private_key=user_data['encrypted_private_key'].encode(),
                    derived_key_hash=user_data['derived_key_hash']
                )
                db.session.add(user)
                db.session.flush()
                logger.info(f"New user added to the db: {user.username}")

                for tag_data in item['tags']:
                    tag = Tag(
                        name=tag_data['name'],
                        description=tag_data['description'],
                        color_red=tag_data['color_red'],
                        color_green=tag_data['color_green'],
                        color_blue=tag_data['color_blue'],
                        date_created=convert_str_to_datetime_utc(tag_data['date_created']),
                        last_updated=convert_str_to_datetime_utc(tag_data['last_updated']),
                        creator_id=user.id
                    )
                    db.session.add(tag)

                    logger.info(f"New tag added to the db: {tag.name}")

                for entry_data in item['journal_entries']:
                    entry = JournalEntry(
                        title=entry_data['title'],
                        content=entry_data['content'],
                        locked=entry_data['locked'],
                        favourite=entry_data['favourite'],
                        date_created=convert_str_to_datetime_utc(entry_data['date_created']),
                        last_updated=convert_str_to_datetime_utc(entry_data['last_updated']),
                        author_id=user.id
                    )
                    db.session.add(entry)
                    db.session.flush()

                    logger.info(f"New journal entry added to the db")

                    for tag_name in entry_data['tags']:
                        tag = Tag.query.filter_by(name=tag_name, creator_id=user.id).first()
                        if tag:
                            entry.tags.append(tag)

            db.session.commit()
            return {'message': 'Data imported successfully'}, 200

        except Exception as e:
            db.session.rollback()
            return {'message': 'Error importing data', 'error': str(e)}, 500