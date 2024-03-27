# manage.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import current_app
from flask.cli import FlaskGroup
import getpass
import logging

from app.extensions import db
from app import create_app
from app.models.user import User

cli = FlaskGroup(create_app=create_app)
logger = logging.getLogger(__name__)

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

        db.session.add(demo_user)
        db.session.commit()
        print("Demo user created successfully!")
        logger.info("Demo user created successfully!")
    except Exception as e:
        print("Couldn't create demo user.")
        logger.error(f"Couldn't create demo user.\nERROR: {e}")
        print(f"\nERROR: {e}")


@cli.command("setup_db")
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


@cli.command("all_users")
def all_users():
    """
    Command-line utility to retrieve and print all users' email addresses.

    This command queries the database and prints the email addresses of all registered users.

    Usage:
        python manage.py all_users

    Example:
        $ python manage.py all_users
        user1@example.com
        user2@example.com
        ...

    Returns:
        None
    """
    with current_app.app_context():
        users = User.query.all()
        if users:
            for user in users:
                print(user.username, user.email, user.is_admin)
        else:
            print("No users found!")


@cli.command("create_admin")
def create_admin():
    """Creates the admin user."""
    fullname = input("Enter fullname: ")
    username = input("Enter a username: ")
    email = input("Enter email address: ")
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Enter password again: ")
    if password != confirm_password:
        print("Passwords don't match")
    else:
        try:
            user = User(
                fullname=fullname,
                username=username,
                email=email,
                is_admin=True
            )
            user.set_hashed_password(password)

            db.session.add(user)
            db.session.commit()
            print(f"Admin with email {email} created successfully!")
            logger.info(f"Admin with email {email} created successfully!")
        except Exception as e:
            print("Couldn't create admin user.")
            logger.error(f"Couldn't create admin.\nERROR: {e}")
            print(f"\nERROR: {e}")


if __name__ == '__main__':
    cli()