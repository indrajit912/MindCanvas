# manage.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import current_app
from flask.cli import FlaskGroup
from app.extensions import db
from app.models.models import User
import getpass
import logging

cli = FlaskGroup(current_app)
logger = logging.getLogger(__name__)

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
        for user in users:
            print(user.username, user.email, user.is_admin)


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