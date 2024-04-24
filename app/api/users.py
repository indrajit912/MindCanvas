# app/api/users.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 25, 2024
# 
from flask_restful import Resource, reqparse
from flask import request
from sqlalchemy import extract
from cryptography.fernet import Fernet
from app.models.user import User
from app.models.tag import Tag
from app.models.journal_entry import JournalEntry
from app.extensions import db
from app.utils.user_utils import update_user
from app.utils.decorators import token_required
from scripts.utils import utcnow

class UsersResource(Resource):
    """
    - GET /api/users - Get all users in the db
    - GET /api/users/<string:username> - Get user by username
    """
    @token_required
    def get(self, username=None):
        if username:
            user = User.query.filter_by(username=username).first()
            if user:
                return user.json(), 200
            else:
                return {'message': 'User not found'}, 404
        else:
            users = {'users': [u.json() for u in User.query.all()]}
            return users, 200
    

class UserResource(Resource):
    """
    Once your Flask app is running, you can access the APIs by sending HTTP requests to the specified endpoints. 
    For example:

     - GET /api/users/<user_id> - Get a specific user
     - POST /api/create/user/ - Create new user
     - PUT /api/users/<user_id> - Update a specific user
     - DELETE /api/users/<user_id> - Delete a specific user
    """
    @token_required
    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        return user.json()
    
    @token_required
    def post(self):

        parser = reqparse.RequestParser()
        parser.add_argument('fullname', type=str, required=True, help='Fullname is required')
        parser.add_argument('email', type=str, required=True, help='Email is required')
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('email_verified', type=bool, required=False)
        
        args = parser.parse_args()

        # Check if the user already exists
        existing_user = User.query.filter(
            (User.username == args['username']) | (User.email == args['email'])
        ).first()
        if existing_user:
            if existing_user.email == args['email']:
                return {'message': 'User with this email already exists'}, 400
            else:
                return {'message': 'User with this username already exists'}, 400

        # Create a new user
        new_user = User(
            fullname=args['fullname'],
            email=args['email'],
            username=args['username'],
        )
        new_user.set_hashed_password(args['password'])

        # Set private key
        user_key = Fernet.generate_key()
        new_user.set_encrypted_private_key(private_key=user_key, password=args['password'])

        if args.get('email_verified') is not None:
            new_user.email_verified = args.get('email_verified')

        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()

        return new_user.json(), 200

    @token_required
    def put(self, user_id):
        """
        Update user information.

        Updates the user information based on the provided data. The request body should contain 
        optional fields to update the user's fullname, email, username, is_admin, and email_verified status.

        Example Request:
        PUT /users/<user_id>
        {
            "fullname": "John Doe",
            "email": "john@example.com",
            "username": "johndoe",
            "is_admin": true,
            "email_verified": false
        }

        - Requires a bearer token in the request header for authentication. For example,
            headers = {
              'Authorization': f"Bearer {current_app.config['SECRET_API_TOKEN']}"
            }

        If the 'password' field is included in the request, it returns a 400 error response with 
        the message "Password cannot be updated through this API.".

        Returns:
            - If the user is updated successfully, returns a 200 response with a message:
              {'message': 'User updated successfully'}.
            - If an error occurs during the update process, returns an error response with the appropriate status code 
              and error message.

        """
        parser = reqparse.RequestParser()
        parser.add_argument('fullname', type=str)
        parser.add_argument('email', type=str)
        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)
        parser.add_argument('is_admin', type=bool)
        parser.add_argument('email_verified', type=bool)

        args = parser.parse_args()

        if args['password']:
            return {"message": "Password cannot be updated through this API."}, 400

        status_code, message = update_user(user_id=user_id, data=args)

        if status_code == 200:
            return {'message': 'User updated successfully'}, 200
        else:
            return message, status_code



    @token_required
    def delete(self, user_id):
        # Retrieve the user to delete
        user = User.query.get_or_404(user_id)

        # Delete the user from the database
        db.session.delete(user)
        db.session.commit()

        return {'message': 'User deleted successfully'}, 200


class ChangeUserPassword(Resource):
    """
    - POST '/api/users/<int:user_id>/change_password'
        body {"new_password": "KD84djkf@dkf", "private_key": "dsklfkiDKKFO93234jkdlf"}
    """
    @token_required
    def post(self, user_id):

        parser = reqparse.RequestParser()
        parser.add_argument('new_password', type=str, required=True, help='Give a new password')
        parser.add_argument('private_key', type=str, required=True, help='User private key is required')

        args = parser.parse_args()

        # Retrieve the user from the database using user_id
        user = User.query.get_or_404(user_id)
        
        # Set the new password hash using the method `User.set_hashed_password(new_passwd)`
        user.set_hashed_password(args.get('new_password'))

        # Set user's encrypted private key with new_passwd using the method 
        # User.set_encrypted_private_key(private_key=user_private_key, password=new_passwd)
        user.set_encrypted_private_key(
            private_key = args.get('private_key'),
            password = args.get('new_password')
        )
        
        # Commit the changes to the database
        db.session.commit()
        
        return {'message': 'Password changed successfully.'}, 200
    

    
class UpdateLastSeen(Resource):
    """
    - POST '/api/users/<int:user_id>/update_last_seen'
    """
    @token_required
    def post(self, user_id):
        # Retrieve the user from the database using user_id
        user = User.query.get_or_404(user_id)
        
        # Update the last_seen attribute of the user
        user.last_seen = utcnow()
        
        # Commit the changes to the database
        db.session.commit()
        
        return {'message': 'last_seen attribute updated successfully'}, 200


class OnThisDayEntriesResource(Resource):
    """
    GET /api/users/<string:username>/journal_entries?today=MM-DD
    Get all journal entries of a particular user on a given month and day (MM-DD).
    """
    @token_required
    def get(self, username):
        date = request.args.get('today')  # Get the date from query parameters (format: MM-DD)
        if not date or len(date) != 5 or date[2] != '-':
            return {'message': 'Date parameter in MM-DD format is required'}, 400

        # Extract month and day from the date string
        month = int(date[:2])
        day = int(date[3:])

        # Query journal entries for the specified user on the given month and day
        user = User.query.filter_by(username=username).first()
        if not user:
            return {'message': 'User not found'}, 404

        # Filter journal entries by month and day
        query = JournalEntry.query.filter(
            (JournalEntry.author_id == user.id) &
            (extract('month', JournalEntry.date_created) == month) &
            (extract('day', JournalEntry.date_created) == day)
        )

        # Execute the query
        journal_entries = query.all()

        # Serialize journal entries into JSON format
        entries_json = [entry.json() for entry in journal_entries]

        return {'journal_entries': entries_json}, 200
    

class UserTagsResource(Resource):
    """
    - GET /api/users/<string:username>/tags - Get all tags of a given user.
    """
    @token_required
    def get(self, username):
        # Retrieve the user
        user = User.query.filter_by(username=username).first()
        if not user:
            return {'message': 'User not found'}, 404

        # Retrieve all tags associated with the user
        tags = Tag.query.filter_by(creator_id=user.id).all()

        # Serialize tags into JSON format
        tags_json = [tag.json() for tag in tags]

        return {'tags': tags_json}, 200