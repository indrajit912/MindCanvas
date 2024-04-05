# MindCanvas
#
# Author: Indrajit Ghosh
# Created on: Mar 24, 2024
#
# TODO: Create an option to Download/Upload user's data.
# TODO: Encrypt user's journal entry before saving to database.
"""
This script starts the Flask development server to run the web application.

Usage:
    - Run the Flask development server:
    >>> python3 run.py

    - Run the gunicorn server
    >>> /env/bin/gunicorn --bind 0.0.0.0:5000 run:app

Database initialization:
    1. To setup the database for the first time use the following command
on the terminal:

    $ env/bin/python manage.py setup_db

    OR, you can do it manually by the following set of commands on Flask Shell
    $ flask shell
        >>> from app import db
        >>> from app.models.models import *
        >>> db.create_all()

    2. Use the following to run the app locally:
    $ python run.py

Note: Flask Migration
    1. flask db init
    2. flask db migrate -m 'Initial Migrate'
    3. flask db upgrade
    These 2 and 3 you need to do everytime you change some in your db!
"""

from app import create_app
from flask import session, g

app = create_app()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app.config['PORT'])