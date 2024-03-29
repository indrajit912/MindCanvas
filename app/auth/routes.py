# app/auth/routes.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import render_template, url_for, flash, redirect, current_app, request, session
from flask_login import login_user, login_required, current_user, logout_user
from sqlalchemy import desc, extract

from app.forms.auth_forms import UserLoginForm, EmailRegistrationForm, UserRegistrationForm
from app.models.user import User
from app.models.journal_entry import JournalEntry
from app.utils.decorators import logout_required
from app.utils.token import get_token_for_email_registration, confirm_email_registration_token
from scripts.email_message import EmailMessage
from scripts.utils import count_words, convert_utc_to_ist_str, format_years_ago
from config import EmailConfig

import logging
from datetime import datetime
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
                session['entries_unlocked'] = False
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
    
    # Last 10 journal Entries
    user_journal_entries = JournalEntry.query.filter_by(
        author_id=current_user.id
    ).order_by(
        desc(JournalEntry.last_updated)
    ).limit(10).all()

    
    # Get today's date in MM-DD format
    today_date = datetime.now().strftime('%m-%d')

    # Extract month and day from today's date
    month, day = map(int, today_date.split('-'))

    # Get the current year
    current_year = datetime.now().year

    # Query journal entries for the current user on the given month and day, excluding the current year
    onthis_day_journal = JournalEntry.query.filter(
        (JournalEntry.author_id == current_user.id) &
        (extract('month', JournalEntry.date_created) == month) &
        (extract('day', JournalEntry.date_created) == day) &
        (extract('year', JournalEntry.date_created) != current_year)
    ).all()

    return render_template(
        'dashboard.html', 
        user=user,
        user_journal_entries = user_journal_entries,
        onthis_day_journal=onthis_day_journal,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        format_years_ago=format_years_ago,
        redirect_destination='dashboard'
    )


@auth_bp.route('/unlock-entries/<destination>', methods=['POST'])
@login_required
def unlock_entries(destination):
    password = request.form.get('password')
    print(destination)

    # Check if the password is correct
    if current_user.check_password(password):
        # Save a flag in session indicating that all locked entries are unlocked
        session['entries_unlocked'] = True
        flash('All locked entries have been successfully unlocked!', 'success')
    else:
        flash('Incorrect password. Please try again.', 'danger')

    # Redirect to the specified destination
    if destination == 'dashboard':
        return redirect(url_for('auth.dashboard'))
    elif destination == 'profile':
        return redirect(url_for('auth.profile'))
    else:
        # Handle invalid destination
        return redirect(url_for('auth.dashboard')) 


@auth_bp.route('/lock-entries/<destination>', methods=['POST'])
@login_required
def lock_entries(destination):
    password = request.form.get('password')

    # Check if the password is correct
    if current_user.check_password(password):
        # Save a flag in session indicating that all locked entries are unlocked
        session['entries_unlocked'] = False
        flash('All unlocked entries have been successfully locked!', 'success')
    else:
        flash('Incorrect password. Please try again.', 'danger')

    # Redirect to the specified destination
    if destination == 'dashboard':
        return redirect(url_for('auth.dashboard'))
    elif destination == 'profile':
        return redirect(url_for('auth.profile'))
    else:
        # Handle invalid destination
        return redirect(url_for('auth.dashboard')) 


@auth_bp.route('/profile')
@login_required
def profile():
    # Get the current user's journal entries and tags
    journal_entries = current_user.journal_entries
    tags = current_user.tags
    # Query the database for the last six journal entries of the current user
    user_journal_entries = JournalEntry.query.filter_by(
        author_id=current_user.id
    ).order_by(
        JournalEntry.date_created.desc()
    ).limit(6).all()
    
    # Count the total number of journal entries, tags, and words
    total_journal_entries = len(journal_entries)
    total_tags = len(tags)
    total_words_in_journal_entries = sum(count_words(entry.content) for entry in journal_entries)
    
    # Pass the count_words function to the template
    return render_template(
        'profile.html',
        user=current_user, 
        total_journal_entries=total_journal_entries, 
        total_tags=total_tags, 
        total_words_in_journal_entries=total_words_in_journal_entries,
        user_journal_entries=user_journal_entries,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='profile'
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
        response = requests.post(
            api_user_post_url, 
            json=new_user_data,
            headers={'Authorization': f"Bearer {current_app.config['SECRET_API_TOKEN']}"}
        )

        if response.status_code == 200:
            # Capture the user_json sent by the POST request.
            user_json = response.json()
            logger.info(f"A new user registered with the username `{user_json['username']}`.")
            flash("You have successfully registered! You may now log in using these credentials.", 'success')
            return redirect(url_for('auth.login'))
        else:
            logger.error("Failed to register the user.")
            flash('Failed to register user. Please try again.', 'danger')

    return render_template('register_user.html', form=form, user_data=user_data)

