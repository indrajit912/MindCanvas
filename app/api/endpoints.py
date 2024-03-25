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

class UserResource(Resource):
    """
    Once your Flask app is running, you can access the APIs by sending HTTP requests to the specified endpoints. For example:

     - GET /api/users - Get all users
     - POST /api/users - Create a new user
     - GET /api/users/<user_id> - Get a specific user
     - PUT /api/users/<user_id> - Update a specific user
     - DELETE /api/users/<user_id> - Delete a specific user
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
        parser.add_argument('is_admin', type=bool, default=False)  # Add is_admin argument with default value False
        
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

        return {'message': 'User created successfully'}, 201

    def put(self, user_id):
        parser = reqparse.RequestParser()
        parser.add_argument('fullname', type=str, required=True, help='Fullname is required')
        parser.add_argument('email', type=str, required=True, help='Email is required')
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('is_admin', type=bool, default=False)  # Add is_admin argument with default value False
        
        args = parser.parse_args()

        # Retrieve the user to update
        user = User.query.get_or_404(user_id)

        # Check if the email or username is already in use by another user
        existing_user = User.query.filter(
            (User.id != user_id) &
            ((User.username == args['username']) | (User.email == args['email']))
        ).first()
        if existing_user:
            if existing_user.email == args['email']:
                return {'message': 'User with this email already exists'}, 400
            else:
                return {'message': 'User with this username already exists'}, 400

        # Update the user
        user.fullname = args['fullname']
        user.email = args['email']
        user.username = args['username']
        user.is_admin = args['is_admin']
        user.set_hashed_password(args['password'])

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


api.add_resource(UserResource, '/users', '/users/<int:user_id>')