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
     - POST /api/create/tag/ - Create new Tag
     - PUT /api/tag/<tag_id> - Update a specific Tag
     - DELETE /api/tag/<tag_id> - Delete a specific Tag
    """
    @token_required
    def get(self, tag_id):
        tag = Tag.query.get_or_404(tag_id)
        return tag.json()
    
    @token_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True, help='Name is required')
        parser.add_argument('creator_id', type=int, required=True, help='The `creator_id` is required')
        parser.add_argument('color_red', type=int, required=False)
        parser.add_argument('color_green', type=int, required=False)
        parser.add_argument('color_blue', type=int, required=False)
        parser.add_argument('description', type=str, required=False)
        
        args = parser.parse_args()

        # Preprocess the tag name for comparison
        processed_name = Tag.preprocess_tag_name(args['name'])
    
        # Check if a tag with the same name already exists
        existing_tag = Tag.query.filter_by(name=processed_name).first()
        if existing_tag:
            return {'message': 'Tag with the same name already exists'}, 400

        # Create a new Tag
        new_tag = Tag(
            name=args['name'],
            creator_id=args['creator_id'],
            color_red=args.get('color_red'),
            color_green=args.get('color_green'),
            color_blue=args.get('color_blue'),
            description=args.get('description')
        )

        # Add the new_tag to the database
        db.session.add(new_tag)
        db.session.commit()

        return new_tag.json(), 200
    

    @token_required
    def put(self, tag_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=False)
        parser.add_argument('color_red', type=int, required=False)
        parser.add_argument('color_green', type=int, required=False)
        parser.add_argument('color_blue', type=int, required=False)
        parser.add_argument('description', type=str, required=False)
        
        args = parser.parse_args()

        # Find the tag by ID
        tag = Tag.query.get_or_404(tag_id)

        # Update the tag attributes if provided
        if args['name'] is not None:
            # Preprocess the tag name for comparison
            processed_name = Tag.preprocess_tag_name(args['name'])

            # Check if a tag with the same name already exists
            existing_tag = Tag.query.filter_by(name=processed_name).first()
            if existing_tag:
                return {'message': 'Tag with the same name already exists'}, 400
            tag.name = args['name']

        if args['color_red'] is not None:
            tag.color_red = args['color_red']
    
        if args['color_green'] is not None:
            tag.color_green = args['color_green']

        if args['color_blue'] is not None:
            tag.color_blue = args['color_blue']

        if args['description'] is not None:
            tag.description = args['description']

        tag.last_updated = utcnow()

        # Commit the changes to the database
        db.session.commit()

        return tag.json(), 200
    
    @token_required
    def delete(self, tag_id):
        tag = Tag.query.get_or_404(tag_id)
        db.session.delete(tag)
        db.session.commit()
        return {"message": "Tag deleted successfully"}, 200