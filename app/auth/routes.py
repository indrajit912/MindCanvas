# app/auth/routes.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import render_template, url_for, flash, redirect, request, current_app
from flask_login import login_user, login_required, current_user, logout_user
from sqlalchemy import desc

from app.forms.auth_forms import UserLoginForm, EmailRegistrationForm, UserRegistrationForm
from app.models.models import User, JournalEntry, Tag
from app.utils.decorators import logout_required
from app.utils.token import get_token_for_email_registration, confirm_email_registration_token
from scripts.utils import convert_utc_to_ist
from scripts.email_message import EmailMessage
from config import EmailConfig

from datetime import datetime
import logging
import requests

from . import auth_bp

logger = logging.getLogger(__name__)


# Login view (route)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()

    # Login logic here
    if form.validate_on_submit():

        # Check if the user provided username or email
        user = User.query.filter((User.username == form.username_or_email.data) | (User.email == form.username_or_email.data)).first()

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


@auth_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = current_user
    user_journal_entries = JournalEntry.query.filter_by(user_id=current_user.id).order_by(desc(JournalEntry.last_updated)).all()
    return render_template(
        'dashboard.html', 
        user=user,
        user_journal_entries = user_journal_entries,
        convert_utc_to_ist=convert_utc_to_ist
    )


@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully!", 'success')
    logger.info("User logged out successfully.")

    return redirect(url_for('auth.login'))

@auth_bp.route('/register_email', methods=['GET', 'POST'])
@logout_required
def register_email():
    form = EmailRegistrationForm()

    if form.validate_on_submit():
        # Check whether the email already exists in the database
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash("Email id taken. Try different one!", 'warning')
            return redirect(url_for('auth.register_email'))
        else:
            # Get the token
            token = get_token_for_email_registration(fullname=form.fullname.data, email=form.email.data)
            acc_registration_url = url_for('auth.register_user', token=token, _external=True)
            
            # Send acc_registration_url to the new user form.email.data.
            _email_html_text = render_template(
                'emails/email_register.html',
                acc_registration_url=acc_registration_url,
                username=form.fullname.data
            )

            msg = EmailMessage(
                sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                to=form.email.data,
                subject="AdNotifier: New Account Registration",
                email_html_text=_email_html_text
            )

            try:
                msg.send(
                    sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                    server_info=EmailConfig.GMAIL_SERVER,
                    print_success_status=False
                )

                flash('Almost there! New account registration instructions sent to your email. Please check and follow the link.', 'info')
                logger.info(f"New acc registration instruction sent over email to '{form.email.data}'.")
                form = EmailRegistrationForm(formdata=None)
                return render_template('register_email.html', form=form)
            
            except Exception as e:
                # TODO: Handle email sending error better
                flash('An error occurred while attempting to send the account registration link through email. Try again!', 'danger')
                logger.error("Error occurred while attempting to send the account registration link through email.")
                return redirect(url_for('auth.register_email'))


    return render_template('register_email.html', form=form)

@auth_bp.route('/register_user/<token>', methods=['GET', 'POST'])
def register_user(token):
    user_data = confirm_email_registration_token(token)

    if not user_data:
        flash('Invalid or expired reset token. Please try again.', 'danger')
        return redirect(url_for('auth.register_email'))
    
    form = UserRegistrationForm()

    if form.validate_on_submit():
        # Prepare data for the POST request
        new_user_data = {
            'fullname': user_data['fullname'],
            'email': user_data['email'],
            'username': form.username.data,
            'password': form.passwd.data
        }

        # Send POST request to the API
        api_user_post_url = current_app.config['HOST'] + '/api/user'
        response = requests.post(api_user_post_url, json=new_user_data)

        if response.status_code == 201:
            flash('User registered successfully!', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Failed to register user. Please try again.', 'danger')

    return render_template('register_user.html', form=form, user_data=user_data)

