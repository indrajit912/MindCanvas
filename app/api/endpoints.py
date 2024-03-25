# app/api/user_api
# 
# Author: Indrajit Ghosh
# Created On: Mar 25, 2024
# 
from flask import jsonify
from flask_restful import Api, Resource, reqparse
from app.models.models import User
from app.extensions import db

from . import api_bp

api = Api(api_bp)

class UsersResource(Resource):
    """
    - GET /api/users - Get all users in the db
    """
    def get(self):
        users = {'users': [u.json() for u in User.query.all()]}
        return jsonify(users)

class UserResource(Resource):
    """
    TODO: Add API_KEY base authentication
    Once your Flask app is running, you can access the APIs by sending HTTP requests to the specified endpoints. 
    For example:

     - GET /api/user/<user_id> - Get a specific user
     - POST /api/user/ - Create new user
     - PUT /api/user/<user_id> - Update a specific user
     - DELETE /api/user/<user_id> - Delete a specific user
    """

    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        return jsonify(user.json())
    
    def post(self):

        parser = reqparse.RequestParser()
        parser.add_argument('fullname', type=str, required=True, help='Fullname is required')
        parser.add_argument('email', type=str, required=True, help='Email is required')
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('is_admin', type=bool, default=False)
        
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
            is_admin=args['is_admin']
        )
        new_user.set_hashed_password(args['password'])

        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()

        return new_user.json(), 201

    def put(self, user_id): 

        parser = reqparse.RequestParser()
        parser.add_argument('fullname', type=str)
        parser.add_argument('email', type=str)
        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)
        parser.add_argument('is_admin', type=bool)

        args = parser.parse_args()

        # Retrieve the user to update
        user = User.query.get_or_404(user_id)

        # Check if the email or username is already in use by another user
        if args.get('email') or args.get('username'):
            existing_user = User.query.filter(
                (User.id != user_id) &
                ((User.username == args.get('username')) | (User.email == args.get('email')))
            ).first()
            if existing_user:
                if existing_user.email == args.get('email'):
                    return {'message': 'User with this email already exists'}, 400
                else:
                    return {'message': 'User with this username already exists'}, 400

        # Update the user attributes if provided in the request
        if args.get('fullname'):
            user.fullname = args.get('fullname')
        if args.get('email'):
            user.email = args.get('email')
        if args.get('username'):
            user.username = args.get('username')
        if args.get('is_admin') is not None:
            user.is_admin = args.get('is_admin')
        if args.get('password'):
            user.set_hashed_password(args.get('password'))

        # Commit changes to the database
        db.session.commit()

        return {'message': 'User updated successfully'}, 200

    def delete(self, user_id):
        # Retrieve the user to delete
        user = User.query.get_or_404(user_id)

        # Delete the user from the database
        db.session.delete(user)
        db.session.commit()

        return {'message': 'User deleted successfully'}, 200


api.add_resource(UsersResource, '/users')
api.add_resource(UserResource, '/user', '/user/<int:user_id>')
