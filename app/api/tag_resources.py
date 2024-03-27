# app/api/journal_entries.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 27, 2024
# 
from flask_restful import Resource, reqparse
from app.models.journal_entry import JournalEntry
from app.models.tag import Tag
from app.extensions import db
from app.utils.decorators import token_required
from scripts.utils import utcnow


class TagsResource(Resource):
    """
    API Endpoints:

    - GET /api/tags - Get all tags
    """

    @token_required
    def get(self):
        return {'tags': [t.json() for t in Tag.query.all()]}, 200
    

class TagResource(Resource):
    """
    Once your Flask app is running, you can access the APIs by sending HTTP requests to the specified endpoints. 
    For example:

     - GET /api/tag/<tag_id> - Get a specific Tag
     - POST /api/tag/ - Create new Tag
     - PUT /api/tag/<tag_id> - Update a specific Tag
     - DELETE /api/tag/<tag_id> - Delete a specific Tag
    """
    @token_required
    def get(self, tag_id):
        tag = Tag.query.get_or_404(tag_id)
        return tag.json()