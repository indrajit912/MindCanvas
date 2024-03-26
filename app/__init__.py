# app/__init__.py
# Webapp MindCanvas
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024

from flask import Flask
from flask_restful import Api
import logging
from config import get_config, LOG_FILE
from .extensions import db, migrate, login_manager

def configure_logging(app:Flask):
    logging.basicConfig(
        format='[%(asctime)s] %(levelname)s %(name)s: %(message)s',
        filename=str(LOG_FILE)
    )

    if app.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        
        # Fix werkzeug handler in debug mode
        logging.getLogger('werkzeug').handlers = []


def create_app(config_class=get_config()):
    """
    Creates an app with specific config class
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initializing api
    api = Api(app, prefix='/api')

    # Configure logging
    configure_logging(app)

    # Register error handlers
    from app.error_handlers import page_not_found, internal_server_error
    app.register_error_handler(404, page_not_found)
    app.register_error_handler(500, internal_server_error)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Register api resources
    from app.api.users import UsersResource
    api.add_resource(UsersResource, '/users')

    from app.api.users import UserResource
    api.add_resource(UserResource, '/user', '/user/<int:user_id>')

    # Register blueprints
    from app.main import main_bp
    app.register_blueprint(main_bp)

    from app.auth import auth_bp
    app.register_blueprint(auth_bp)

    from app.admin import admin_bp
    app.register_blueprint(admin_bp)

    # Define the user loader function
    @login_manager.user_loader
    def load_user(user_id):
        # Replace this with the actual code to load a user from the database
        from app.models.models import User  # Import your User model
        return User.query.get(int(user_id))

    @app.route('/test/')
    def test():
        return '<h1>Testing the Flask Application!</h1>'

    return app

