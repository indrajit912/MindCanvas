# app/api/journal_entries.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 27, 2024
# Modified On: Apr 24, 2024
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
    - GET /api/tags/<tag_uuid> - Get a specific tag by UUID
    - DELETE /api/tags/<tag_uuid> - Delete a specific tag by UUID
    """

    @token_required
    def get(self, tag_uuid:str=None):
        """
        Get all tags or a specific tag by UUID.

        Parameters:
            tag_uuid (str): Optional. UUID of the tag to retrieve.

        Returns:
            dict: A dictionary containing either a list of all tags or the details of a specific tag.
        """
        if tag_uuid:
            tag = Tag.query.filter_by(uuid=tag_uuid).first_or_404()
            return tag.json()
        
        return {'tags': [t.json() for t in Tag.query.all()]}, 200
    
    @token_required
    def delete(self, tag_uuid):
        """
        Delete a specific tag by UUID.

        Parameters:
            tag_uuid (str): UUID of the tag to delete.

        Returns:
            dict: A message confirming the deletion of the tag.
        """
        tag = Tag.query.filter_by(uuid=tag_uuid).first_or_404()
        db.session.delete(tag)
        db.session.commit()
        return {"message": "Tag deleted successfully"}, 200


    