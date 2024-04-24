# app/__init__.py
# Webapp MindCanvas
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024

# Standard library imports
import logging

# Third-party imports
from flask import Flask
from flask_restful import Api

# Local application imports
from config import get_config, LOG_FILE
from .extensions import db, migrate, login_manager, ckeditor


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

    # Configure logging
    configure_logging(app)

    # Register error handlers
    from app.error_handlers import page_not_found, internal_server_error, bad_request, \
        unauthorized, forbidden
    app.register_error_handler(400, bad_request)
    app.register_error_handler(401, unauthorized)
    app.register_error_handler(403, forbidden)
    app.register_error_handler(404, page_not_found)
    app.register_error_handler(500, internal_server_error)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    ckeditor.init_app(app)
    login_manager.login_view = 'auth.login'

    # Initializing api
    api = Api(app, prefix='/api')
    
    # Register api resources
    from app.api.users import UsersResource, UserResource, OnThisDayEntriesResource, UserTagsResource, \
        UpdateLastSeen, ChangeUserPassword
    api.add_resource(UsersResource, '/users', '/users/<string:username>')
    api.add_resource(UserResource, '/create/user', '/users/<int:user_id>')
    api.add_resource(OnThisDayEntriesResource, '/users/<string:username>/journal_entries')
    api.add_resource(UserTagsResource, '/users/<string:username>/tags')
    api.add_resource(UpdateLastSeen, '/users/<int:user_id>/update_last_seen')
    api.add_resource(ChangeUserPassword, '/users/<int:user_id>/change_password')

    from app.api.journal_entries import JournalEntryResource, UserJournalEntriesResource, \
        SearchJournalEntriesResource
    api.add_resource(JournalEntryResource, '/create/journal_entry', '/journal_entries/<int:journal_entry_id>')
    api.add_resource(UserJournalEntriesResource, '/users/<int:user_id>/journal_entries')
    api.add_resource(SearchJournalEntriesResource, '/users/<int:user_id>/journal_entries/<string:query>')

    from app.api.tag_resources import TagsResource, TagResource
    api.add_resource(TagsResource, '/tags')
    api.add_resource(TagResource, '/create/tag', '/tags/<int:tag_id>')

    from app.api.db_resources import ExportDBResource, ImportDBResource
    api.add_resource(ExportDBResource, '/export_db')
    api.add_resource(ImportDBResource, '/import_db')

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
        from app.models.user import User  # Import your User model
        return User.query.get(int(user_id))

    @app.route('/test/')
    def test():
        return '<h1>Testing the Flask Application!</h1>'

    return app

