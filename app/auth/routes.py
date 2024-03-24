# app/auth/routes.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import render_template, url_for, flash, redirect
from flask_login import login_user

from app.forms.auth_forms import UserLoginForm
from app.models.models import User

from datetime import datetime
import logging

from . import auth_bp

logger = logging.getLogger(__name__)


# Login view (route)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()

    # Login logic here
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            # Check the hash
            if user.check_password(form.passwd.data):
                # Password matched!
                login_user(user)
                flash("Login successful!", 'success')
                logger.info(f"User '{user.email}' successfully logged in.")

                return redirect(url_for('auth.dashboard'))
            else:
                flash("Wrong passsword. Try again!", 'error')
        else:
            flash("That user doesn't exist! Try again...", 'error')
        
        form = UserLoginForm(formdata=None)


    return render_template('login.html', form=form)