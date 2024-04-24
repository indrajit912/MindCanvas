# app/api/journal_entries.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 27, 2024
# Modified On: Apr 24, 2024
# 
from flask import jsonify
from flask_restful import Resource
from app.models.user import User
from app.models.journal_entry import JournalEntry
from app.extensions import db
from app.utils.decorators import token_required


class JournalEntryResource(Resource):
    """
    Once your Flask app is running, you can access the APIs by sending HTTP requests to the specified endpoints. 
    For example:

     - GET /api/journal_entries/<journal_entry_uuid> - Get a specific journal entry
     - DELETE /api/journal_entries/<journal_entry_uuid> - Delete a specific journal entry
    """
    @token_required
    def get(self, journal_entry_uuid):
        journal_entry = JournalEntry.query.filter_by(uuid=journal_entry_uuid).first_or_404()
        return journal_entry.json()

    @token_required
    def delete(self, journal_entry_uuid):
        journal_entry = JournalEntry.query.filter_by(uuid=journal_entry_uuid).first_or_404()
        db.session.delete(journal_entry)
        db.session.commit()
        return {"message": "Journal entry deleted successfully"}, 200

    
class UserJournalEntriesResource(Resource):
    """
    API Resource to handle requests related to journal entries of a specific user.

    - GET /api/users/<user_id>/journal_entries
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
