# app/api/user_data.py
# 
# Author: Indrajit Ghosh
# Created On: Apr 01, 2024
# 

from flask import request
from flask_restful import Resource
from app.models.tag import Tag
from app.models.journal_entry import JournalEntry
from app.extensions import db
from app.utils.decorators import token_required
from flask_login import current_user

class UserDataResource(Resource):
    def get(self):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            return {'message': 'User is not authenticated'}, 401

        # Retrieve user's data
        user_data = {
            'user': current_user.json(),
            'journal_entries': [entry.json() for entry in current_user.journal_entries],
            'tags': [tag.json() for tag in current_user.tags]
        }

        return user_data

    def post(self):
        # TODO: Check this endpoint carefully
        # Check if user is authenticated
        if not current_user.is_authenticated:
            return {'message': 'User is not authenticated'}, 401

        # Parse JSON data from request
        data = request.get_json()

        # Validate JSON structure
        if 'user' not in data or 'journal_entries' not in data or 'tags' not in data:
            return {'message': 'Invalid JSON structure'}, 400

        # Update user's data
        try:
            # Update user's information
            user_info = data['user']
            current_user.username = user_info['username']
            current_user.fullname = user_info['fullname']
            current_user.email = user_info['email']
            current_user.is_admin = user_info['is_admin']

            # Update user's journal entries
            journal_entries = data['journal_entries']
            for entry_data in journal_entries:
                entry = JournalEntry.query.get(entry_data['id'])
                if entry:
                    entry.title = entry_data['title']
                    entry.content = entry_data['content']
                    entry.locked = entry_data['locked']

            # Update user's tags
            tags = data['tags']
            for tag_data in tags:
                tag = Tag.query.get(tag_data['id'])
                if tag:
                    tag.name = tag_data['name']
                    tag.description = tag_data['description']
                    tag.color_red = tag_data['color_red']
                    tag.color_green = tag_data['color_green']
                    tag.color_blue = tag_data['color_blue']

            # Commit changes to the database
            db.session.commit()

            return {'message': 'User data updated successfully'}, 200
        except Exception as e:
            return {'message': 'Failed to update user data', 'error': str(e)}, 500
