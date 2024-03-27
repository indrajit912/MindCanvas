# app/api/journal_entries.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 27, 2024
# 
from flask import jsonify
from flask_restful import Resource, reqparse
from app.models.user import User
from app.models.journal_entry import JournalEntry
from app.models.tag import Tag
from app.extensions import db
from app.utils.decorators import token_required
from scripts.utils import utcnow


class JournalEntryResource(Resource):
    """
    Once your Flask app is running, you can access the APIs by sending HTTP requests to the specified endpoints. 
    For example:

     - GET /api/journal_entry/<journal_entry_id> - Get a specific journal entry
     - POST /api/journal_entry/ - Create new journal entry
     - PUT /api/journal_entry/<journal_entry_id> - Update a specific journal entry
     - DELETE /api/journal_entry/<journal_entry_id> - Delete a specific journal entry
    """
    @token_required
    def get(self, journal_entry_id):
        journal_entry = JournalEntry.query.get_or_404(journal_entry_id)
        return journal_entry.json()
    
    @token_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('title', type=str, required=True, help='Title is required')
        parser.add_argument('content', type=str, required=True, help='Content is required')
        parser.add_argument('user_id', type=int, required=True, help='User ID is required')
        parser.add_argument('tags', type=str, action='append', required=False, help='List of tag names')

        args = parser.parse_args()

        # Create a new Journal Entry
        new_journal_entry = JournalEntry(
            title=args['title'],
            content=args['content'],
            user_id=args['user_id']
        )

        # Add tags to the journal entry
        if args.get('tags'):
            for tag_name in args['tags']:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    # If tag does not exist, create a new tag
                    tag = Tag(
                        name=tag_name, 
                        creator_id=args['user_id'],
                        color_red=128,
                        color_green=128,
                        color_blue=128
                    )
                    db.session.add(tag)
                new_journal_entry.tags.append(tag)

        # Add the new_journal_entry to the database
        db.session.add(new_journal_entry)
        db.session.commit()

        return new_journal_entry.json(), 200
    

class UserJournalEntriesResource(Resource):
    """
    API Resource to handle requests related to journal entries of a specific user.

    - GET /api/user/<user_id>/journal_entries
    """
    @token_required
    def get(self, user_id):
        # Retrieve the user from the database
        user = User.query.get_or_404(user_id)

        # Access the journal_entries attribute of the user
        user_journal_entries = user.journal_entries

        # Convert the journal entries to JSON format
        journal_entries_json = [journal_entry.json() for journal_entry in user_journal_entries]

        return jsonify(journal_entries_json)