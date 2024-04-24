# manage.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import current_app
from flask.cli import FlaskGroup
import pwinput
import sys
import requests
import argparse
import json
import logging
from pathlib import Path
from cryptography.fernet import Fernet
from tabulate import tabulate
from datetime import datetime, timezone
from config import EmailConfig

from app.extensions import db
from app import create_app
from app.models.user import User
from app.models.tag import Tag
from app.models.journal_entry import JournalEntry
from app.utils.encryption import encrypt
from scripts.app_defaults import default_tags
from config import Config

cli = FlaskGroup(create_app=create_app)
logger = logging.getLogger(__name__)
bullet_unicode = '\u2022'

old_mindcanvas_file = Config.APP_DATA_DIR / "mindcanvas_data.json"

def create_demo_user():
    """
    Helper function to create a demo user.
    """
    try:
        demo_user = User(
            username='demo',
            fullname="Demo User",
            email="demouser@demo.com"
        )
        demo_user.set_hashed_password("password")

        # Set private key
        user_key = Fernet.generate_key()
        demo_user.set_encrypted_private_key(private_key=user_key, password="password")

        db.session.add(demo_user)
        db.session.commit()
        print("Demo user created successfully!")
        logger.info("Demo user created successfully!")
    except Exception as e:
        print("Couldn't create demo user.")
        logger.error(f"Couldn't create demo user.\nERROR: {e}")
        print(f"\nERROR: {e}")


@cli.command("setup-db")
def setup_database():
    """
    Command-line utility to set up the database.

    This command creates all necessary tables in the database based on defined models.

    Usage:
        flask setup_database

    Returns:
        None
    """
    with current_app.app_context():
        db.create_all()
        print("Database tables created successfully!")

        # Check if the demo user exists
        demo_user = User.query.filter_by(username='demo').first()

        if demo_user:
            print("Demo user already exists.")
        else:
            create_demo_user()


@cli.command("all-users")
def all_users():
    """
    Command-line utility to retrieve and print all users' details.

    This command queries the database and prints the details of all registered users.

    Usage:
        python manage.py all_users

    Example:
        $ python manage.py all_users
        +----------+---------------------+-------+
        | Username | Email               | Admin |
        +----------+---------------------+-------+
        | user1    | user1@example.com   | False |
        | user2    | user2@example.com   | True  |
        | ...      | ...                 | ...   |
        +----------+---------------------+-------+

    Returns:
        None
    """
    with current_app.app_context():
        users = User.query.all()
        if users:
            user_data = [
                (user.username, user.email, user.is_admin, User.format_datetime_to_str(user.date_joined)) 
                for user in users
            ]
            headers = ["Username", "Email", "Admin", "Date Joined"]
            print(tabulate(user_data, headers=headers, tablefmt="grid"))
        else:
            print("No users found!")


@cli.command("all-tags")
def all_tags():
    """
    Command-line utility to retrieve and print all tags' details.

    This command queries the database and prints the details of all tags.

    Usage:
        python manage.py all_tags

    Example:
        $ python manage.py all_tags
        +-----------------+---------------------+-------+---------------------------------------------+
        | Name            | Color               | Creator Username    | Date Created                  |
        +-----------------+---------------------+-------+---------------------------------------------+
        | personal-growth | (128, 0, 128)       | indrajit            | Mon, 02 Jan 2023 07:45:00 UTC |
        | health-wellness | (0, 191, 255)       | indrajit            | Mon, 02 Jan 2023 07:45:00 UTC |
        | ...             | ...                 | ...                 | ...                           |
        +-----------------+---------------------+-------+---------------------------------------------+

    Returns:
        None
    """
    with current_app.app_context():
        tags = Tag.query.all()
        if tags:
            tag_data = [
                (tag.name, tag.color_rgb(), tag.creator.username, Tag.format_datetime_to_str(tag.date_created)) 
                for tag in tags
            ]
            headers = ["Name", "Color", "Creator Username", "Date Created"]
            print(tabulate(tag_data, headers=headers, tablefmt="grid"))
        else:
            print("No tags found!")


def _create_indrajit_tags(private_key):
    """
    Creates a number of records for Tag. These are used by Indrajit.
    """
    # Get the user with email=EmailConfig.INDRAJIT912
    indrajit_user = User.query.filter_by(email=EmailConfig.INDRAJIT912_GMAIL).first()
    if not indrajit_user:
        print("Indrajit's user account not found!")
        return
    
    for tag_data in default_tags:
        tag = Tag(
            name=encrypt(tag_data['name'], private_key),
            description=tag_data['description'],
            color_red=tag_data['color_red'],
            color_green=tag_data['color_green'],
            color_blue=tag_data['color_blue'],
            creator_id=indrajit_user.id
        )
        tag.set_name_hash(tag_data['name'])
        db.session.add(tag)


def _create_indrajit_mindcanvas_old_entries(file_path, private_key):
    """
    This creates JournalEntries for indrajit from MindCanvas-Old data

    file_path: `json`
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
        entries = data['entries']

        # Get the user with email=EmailConfig.INDRAJIT912
        indrajit_user = User.query.filter_by(email=EmailConfig.INDRAJIT912_GMAIL).first()
        if not indrajit_user:
            print("Indrajit's user account not found!")
            return
        
        for entry_data in entries:
            # Convert the datetime_utc string to a timezone-aware datetime object
            datetime_utc = datetime.fromisoformat(entry_data['datetime_utc'])
            datetime_utc = datetime_utc.replace(tzinfo=timezone.utc)
            
            # Create a JournalEntry object
            entry = JournalEntry(
                title=encrypt(entry_data['title'], private_key),
                content=encrypt(entry_data['text'], private_key),
                date_created=datetime_utc,
                last_updated=datetime_utc,
                author_id=indrajit_user.id
            )
            
            # Add the entry to the session
            db.session.add(entry)


@cli.command("create-indrajit")
def create_indrajit():
    """Creates the admin Indrajit Ghosh and his associated details."""
    # Check whether Indrajit is in db already
    indrajit_exists = User.query.filter_by(email=EmailConfig.INDRAJIT912_GMAIL).first()

    if indrajit_exists:
        print("Admin `Indrajit` is already in the db!")
        sys.exit()
    
    indrajit_passwd = pwinput.pwinput(
        "Creating the admin `Indrajit Ghosh` ...\nEnter Indrajit's password: ",
        mask=bullet_unicode
    )
    confirm_password = pwinput.pwinput("Enter password again: ", mask=bullet_unicode)
    if indrajit_passwd != confirm_password:
        print("Passwords don't match")
    else:
        try:
            with current_app.app_context():
                # Create Indrajit
                indrajit_data = {
                    "fullname": "Indrajit Ghosh",
                    "username": "indrajit"
                }

                if not EmailConfig.INDRAJIT912_GMAIL:
                    print("Indrajit's email address is not found in the `.env` file! Exiting...")
                    logger.warning("Indrajit's email address is not found in the `.env` file! Exiting...")
                    sys.exit()
                
                indrajit_data['email'] = EmailConfig.INDRAJIT912_GMAIL

                indrajit = User(
                    username = indrajit_data['username'],
                    fullname=indrajit_data['fullname'],
                    email=indrajit_data['email'],
                    is_admin=True,
                    email_verified=True
                )
                indrajit.set_hashed_password(indrajit_passwd)
                indrajit_key = Fernet.generate_key()
                indrajit.set_encrypted_private_key(indrajit_key, indrajit_passwd)

                # Add Indrajit to db
                db.session.add(indrajit)
                print("Admin Indrajit created successfully!")
                logger.info("Admin Indrajit created successfully!")

                db.session.commit()

        except Exception as e:
            print("Some error occurred.")
            logger.error(f"Error occurred while creating records of the admin `Indrajit Ghosh`.\nERROR: {e}")
            print(f"\nERROR: {e}")


def _get_host():
    host = input("Specify the host (e.g- 'https://username.pythonanywhere.com'): ")
    if not host:
        host = 'http://localhost:' + str(current_app.config['PORT'])
    return host


@cli.command("export-db")
def export_db():
    """
    Command-line utility to export database from the API and save it to a JSON file.
    """
    try:
        host = _get_host()
        export_api_endpoint = host + '/api/export_db'
        
        response = requests.get(
            export_api_endpoint,
            headers={"Authorization": f"Bearer {Config.SECRET_API_TOKEN}"}
        )

        if response.status_code == 200:
            with open(Config.APP_DATA_DIR / 'mindcanvas_db.json', 'w') as f:
                json.dump(response.json(), f, indent=4)
            print(f"Data exported successfully from the host '{host}'!")
            logger.info(f"{current_app.config['FLASK_APP_NAME']} db exported from '{host}'")
        else:
            print(f"{current_app.config['FLASK_APP_NAME']} db Export failed. Status code:", response.status_code)
            print(response.content.decode())
            logger.error(f"{current_app.config['FLASK_APP_NAME']} db exported failed!\nEXPORT_ERROR: {response.content.decode()}")
    except requests.exceptions.RequestException as e:
        print(f"Export failed. Error:", e)


@cli.command("import-db")
def import_db():
    """
    Command-line utility to import data from a JSON file and send it to the API.
    """
    try:
        host = _get_host()

        # Ask user for confirmation before importing data
        confirmation = input("Are you sure you want to import data? This will overwrite existing data. (yes/no): ")
        if confirmation.lower() != 'yes':
            print("Import aborted.")
            return

        # Make the import api endpoint
        import_db_api_endpoint = host + '/api/import_db'
        # Load data from exported file
        data_json_file = Config.APP_DATA_DIR / 'mindcanvas_db.json'
        if not data_json_file.exists():
            print(f"No '{data_json_file.name}' found at APP_DATA_DIR! First export the db.")
            return
        
        with open(Config.APP_DATA_DIR / 'mindcanvas_db.json', 'r') as f:
            data = json.load(f)

        # Send POST request to import data
        response = requests.post(
            import_db_api_endpoint, 
            json=data,
            headers={"Authorization": f"Bearer {Config.SECRET_API_TOKEN}"}
        )

        # Check if request was successful (status code 200)
        if response.status_code == 200:
            print(f"{current_app.config['FLASK_APP_NAME']} DB imported successfully! Host: `{host}`.")
            logger.info(f"{current_app.config['FLASK_APP_NAME']} DB imported imported successfully! Host: `{host}`.")
        else:
            print(f"{current_app.config['FLASK_APP_NAME']} DB import failed to the host `{host}`. Status code:", response.status_code, '\n', response.content.decode())
            logger.error(f"{current_app.config['FLASK_APP_NAME']} DB import failed to the host `{host}`.\nDB_IMPORT_ERR: {response.content.decode()}")
    except requests.exceptions.RequestException as e:
        print("Import failed. Error:", e)


def help_command():
    """
    Command-line utility to display help information about available commands.

    Usage:
        python manage.py help

    Returns:
        None
    """
    print("Available commands:")
    print("1. setup-db: Set up the database.")
    print("2. all-users: Retrieve and print all users' details.")
    print("3. all-tags: Retrieve and print all tags' details.")
    print("4. create-indrajit: Create the admin Indrajit Ghosh and his associated details.")
    print("5. export-db: Export the mindcanvas db in a `mindcanvas_db.json` file.")
    print("6. import-db: Import mindcanvas db from a json file obtained from option 5.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Command-line utility for managing MindCanvas.')
    parser.add_argument('command', type=str, nargs='?', help='Command to execute (e.g., setup-db, all-users, all-tags, create-indrajit, export-db, help)')
    args = parser.parse_args()

    if args.command == 'help':
        help_command()
    elif args.command:
        sys.argv = ['manage.py', args.command]  # Modify sys.argv to include the command
        cli.main()  # Use cli.main() to execute the command
    else:
        print("Please provide a valid command. Use 'python manage.py help' to see available commands.")
