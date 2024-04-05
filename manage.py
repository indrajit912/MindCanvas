# manage.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import current_app
from flask.cli import FlaskGroup
import pwinput
import sys
import argparse
import logging
from cryptography.fernet import Fernet
from tabulate import tabulate
from config import EmailConfig

from app.extensions import db
from app import create_app
from app.models.user import User
from app.models.tag import Tag
from scripts.app_defaults import default_tags

cli = FlaskGroup(create_app=create_app)
logger = logging.getLogger(__name__)
bullet_unicode = '\u2022'

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


def _create_indrajit_tags():
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
            name=tag_data['name'],
            description=tag_data['description'],
            color_red=tag_data['color_red'],
            color_green=tag_data['color_green'],
            color_blue=tag_data['color_blue'],
            creator_id=indrajit_user.id
        )
        db.session.add(tag)


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
                    is_admin=True
                )
                indrajit.set_hashed_password(indrajit_passwd)
                indrajit_key = Fernet.generate_key()
                indrajit.set_encrypted_private_key(indrajit_key, indrajit_passwd)

                # Add Indrajit to db
                db.session.add(indrajit)
                print("Admin Indrajit created successfully!")
                logger.info("Admin Indrajit created successfully!")

                # TODO: Create all default tags of Indrajit
                _create_indrajit_tags()

                print("Indrajit's default tags created successfully!")
                logger.info("Indrajit's default tags created successfully!")

                db.session.commit()

        except Exception as e:
            print("Some error occurred.")
            logger.error(f"Error occurred while creating records of the admin `Indrajit Ghosh`.\nERROR: {e}")
            print(f"\nERROR: {e}")


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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Command-line utility for managing Flask application.')
    parser.add_argument('command', type=str, nargs='?', help='Command to execute (e.g., setup-db, all-users, all-tags, create-indrajit, help)')
    args = parser.parse_args()

    if args.command == 'help':
        help_command()
    elif args.command:
        sys.argv = ['manage.py', args.command]  # Modify sys.argv to include the command
        cli.main()  # Use cli.main() to execute the command
    else:
        print("Please provide a valid command. Use 'python manage.py help' to see available commands.")
