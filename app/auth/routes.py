# app/auth/routes.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import render_template, url_for, flash, redirect, current_app, request, session, abort
from flask_login import login_user, login_required, current_user, logout_user
from sqlalchemy import desc, extract

from app.forms.auth_forms import UserLoginForm, EmailRegistrationForm, UserRegistrationForm
from app.forms.user_forms import AddEntryForm, CreateNewTagForm
from app.models.user import User
from app.models.journal_entry import JournalEntry
from app.models.tag import Tag
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
                # TODO: Update the User.last_seen column!
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
    ).limit(3).all()

    # Get today's date in MM-DD format
    today_date = datetime.now().strftime('%m-%d')

    # Extract month and day from today's date
    month, day = today_date.split('-')

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


@auth_bp.route('/users/<int:user_id>/journal_entries')
@login_required
def user_journal_entries(user_id):
    # Check if the current user's ID matches the provided user_id
    if current_user.id != user_id:
        abort(403)  # Forbidden - Current user does not have access to view another user's journal entries

    # Get the current user's journal entries and tags
    journal_entries = current_user.journal_entries
    tags = current_user.tags

    # Count the total number of journal entries, tags, and words
    total_journal_entries = len(journal_entries)
    total_tags = len(tags)
    total_words_in_journal_entries = sum(count_words(entry.content) for entry in journal_entries)

    # Query all JournalEntry objects associated with the specified user_id
    user_journal_entries = JournalEntry.query.filter_by(
        author_id=user_id
    ).order_by(JournalEntry.date_created.desc()).all()

    return render_template(
        'user_all_entries.html',
        user_journal_entries=user_journal_entries,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='user-all-entries',
        total_journal_entries=total_journal_entries,
        total_tags=total_tags,
        total_words_in_journal_entries=total_words_in_journal_entries
    )


@auth_bp.route('/profile')
@login_required
def profile():
    # Get the current user's journal entries and tags
    journal_entries = current_user.journal_entries
    tags = current_user.tags

    # Count the total number of journal entries, tags, and words
    total_journal_entries = len(journal_entries)
    total_tags = len(tags)
    total_words_in_journal_entries = sum(count_words(entry.content) for entry in journal_entries)

    # Query the database for the last five journal entries of the current user
    user_journal_entries = JournalEntry.query.filter_by(
        author_id=current_user.id
    ).order_by(
        JournalEntry.date_created.desc()
    ).limit(3).all()

    
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

@auth_bp.route('/unlock-entries/<destination>', methods=['POST'])
@login_required
def unlock_entries(destination):
    password = request.form.get('password')

    # Check if the password is correct
    if current_user.check_password(password):
        # Save a flag in session indicating that all locked entries are unlocked
        session['entries_unlocked'] = True
        flash('All locked entries have been successfully unlocked!', 'success')
    else:
        flash('Incorrect password. Please try again.', 'error')

    # Redirect to the specified destination
    if destination == 'dashboard':
        return redirect(url_for('auth.dashboard'))
    elif destination == 'profile':
        return redirect(url_for('auth.profile'))
    elif destination == 'user-all-entries':
        return redirect(url_for('auth.user_journal_entries', user_id=current_user.id))
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
        flash('Incorrect password. Please try again.', 'error')

    # Redirect to the specified destination
    if destination == 'dashboard':
        return redirect(url_for('auth.dashboard'))
    elif destination == 'profile':
        return redirect(url_for('auth.profile'))
    elif destination == 'user-all-entries':
        return redirect(url_for('auth.user_journal_entries', user_id=current_user.id))
    else:
        # Handle invalid destination
        return redirect(url_for('auth.dashboard')) 
    
@auth_bp.route('/users/<int:user_id>/manage_tags')
@login_required
def manage_tags(user_id):
    # Check if the current user's ID matches the provided user_id
    if current_user.id != user_id:
        abort(403)  # Forbidden - Current user does not have access to view another user's journal entries

    # Get the current user's tags
    user_tags = current_user.tags

    # Count the total number of journal entries, tags, and words
    total_tags = len(user_tags)

    return render_template(
        'manage_tags.html',
        user_tags=user_tags,
        convert_utc_to_ist_str=convert_utc_to_ist_str
    )
    
@auth_bp.route('/users/<int:user_id>/add_entry', methods=['GET', 'POST'])
@login_required
def add_entry(user_id):
    # Check if the current user is authorized to add an entry for the specified user
    if current_user.id != user_id:
        abort(403)  # Forbidden

    form = AddEntryForm()

    # Tags those are already created by the current_user
    user_tags = current_user.tags

    if form.validate_on_submit():

        # Split the input string to get a list of tags
        tags_for_the_new_entry = [tag.strip() for tag in form.tags.data.split(',') if tag.strip()]

        # Create a json body for the api request
        entry_json = {
            "title": form.title.data,
            "content": form.content.data,
            "author_id": current_user.id,
            "tags": tags_for_the_new_entry,
            "locked": form.locked.data
        }

        # Make a POST request to the API endpoint
        api_url = current_app.config['HOST'] + '/api/create/journal_entry'
        headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
        response = requests.post(api_url, json=entry_json, headers=headers)

        # Check the response status code and flash messages accordingly
        if response.status_code == 200:
            flash('Journal entry added successfully!', 'success')
            logger.info(f"A new JournalEntry added by `{current_user.username}`.")
            # If the user is authorized, redirect to the route
            return redirect(url_for('auth.user_journal_entries', user_id=current_user.id))
        else:
            flash('Failed to add journal entry. Please try again later.', 'error')
            logger.error(f"`{current_user.username}` tried to add a new JournalEntry but error occurred.")


        # Remove the user data
        form = AddEntryForm(formdata=None)

    # Render the add entry form template
    return render_template('add_entry.html', form=form, user_tags=user_tags)


@auth_bp.route('/users/<int:user_id>/create_tag', methods=['GET', 'POST'])
@login_required
def create_tag(user_id):
    # Check if the current user is authorized to add an entry for the specified user
    if current_user.id != user_id:
        abort(403)  # Forbidden

    form = CreateNewTagForm()

    # Tags those are already created by the current_user
    user_tags = current_user.tags

    if form.validate_on_submit():
        # Get the data
        tag_name = Tag.preprocess_tag_name(form.name.data)
        description = form.description.data
        color_red = form.color_red.data
        color_green = form.color_green.data
        color_blue = form.color_blue.data

        tag_data = {
            "name": tag_name,
            "description": description,
            "color_red": color_red,
            "color_green": color_green,
            "color_blue": color_blue,
            "creator_id": current_user.id
        }

        if tag_name in [t.name for t in user_tags]:
            # Redirect
            form.name.data = tag_name
            form.description.data = description
            form.color_red.data = color_red
            form.color_green.data = color_green
            form.color_blue.data = color_blue

            flash(f"The name '{tag_name}' is already in your tag list!", 'info')
            return render_template('create_tag.html', form=form, user_tags=user_tags)


        # Make a POST request to the API endpoint
        api_url = current_app.config['HOST'] + '/api/create/tag'
        headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
        response = requests.post(api_url, json=tag_data, headers=headers)

        # Check the response status code and flash messages accordingly
        if response.status_code == 200:
            flash(f"Your tag '{tag_name}' has been added successfully!", 'success')
            logger.info(f"A new Tag, '{tag_name}' is added by `{current_user.username}`.")
            # If the user is authorized, redirect to the route
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Failed to create the new tag. Please try again later.', 'error')
            logger.error(f"`{current_user.username}` tried to add a new JournalEntry but error occurred.")

        # Remove the user data
        form = CreateNewTagForm(formdata=None)

    # Render the add entry form template
    return render_template('create_tag.html', form=form, user_tags=user_tags)


# Route to handle the POST request to delete a Tag
@auth_bp.route('/delete_tag', methods=['POST'])
@login_required
def delete_tag():
    password = request.form.get('password')
    tag_id = request.form.get('tag_id')

    if not current_user.check_password(password):
        # If the password is not correct, then don't delete the entry
        flash('Incorrect password. Please try again.', 'error')
    else:
        # Make DELETE request to the api
        api_endpoint = f"{current_app.config['HOST']}/api/tags/{tag_id}"
        response = requests.delete(
            api_endpoint,
            headers={'Authorization': f"Bearer {current_app.config['SECRET_API_TOKEN']}"}
        )
        if response.status_code == 200:
            logger.info(f"Tag deleted successfully by {current_user.username}!")
            flash(f"Tag deleted successfully!", "success")
        else:
            logger.error(f"An error occurred while deleting the Tag with ID {tag_id}.")
            flash("An error occurred during Tag deletion. Please try again.", 'error')
    
    
    return redirect(url_for('auth.manage_tags', user_id=current_user.id)) 

    
# Route to toggle the is_admin value
@auth_bp.route('/toggle_entry_lock', methods=['POST'])
@login_required
def toggle_entry_lock():

    # Get the password and `journal_entry_id` from the form
    password = request.form.get('password')
    journal_entry_id  = request.form.get('journal_entry_id')
    destination = request.form.get('destination')

    # Get the JournalEntry by ID
    journal_entry = JournalEntry.query.get_or_404(journal_entry_id)

    # Make sure that the current_user is the author of this journal entry
    if not journal_entry.author_id == current_user.id:
        abort(403)

    # Check if the password is correct
    if current_user.check_password(password):
        # Toggle the locked attribute of the journal_entry
        payload = {"locked": not journal_entry.locked}

        # Make PUT request to the endpoint 
        api_endpoint = f"{current_app.config['HOST']}/api/journal_entries/{journal_entry_id}"
        response = requests.put(
            api_endpoint,
            headers={'Authorization': f"Bearer {current_app.config['SECRET_API_TOKEN']}"},
            json=payload
        )
        
        if response.status_code == 200:
            logger.info(f"`{current_user.username}` changed the `locked` status of one of their JournalEntry.")
            flash("The 'locked' status of the JournalEntry has been updated!", 'success')
        else:
            logger.error(f"Failed to update journal entry locked status. Status code: {response.status_code}\n{response.text}")
            flash(f"API_ERROR: Failed to update journal entry locked status. Status code: {response.status_code}", 'error')
    else:
        flash('Incorrect password. Please try again.', 'error')

    # Redirect to the specified destination
    if destination == 'dashboard':
        return redirect(url_for('auth.dashboard'))
    elif destination == 'profile':
        return redirect(url_for('auth.profile'))
    elif destination == 'user-all-entries':
        return redirect(url_for('auth.user_journal_entries', user_id=current_user.id))
    else:
        # Handle invalid destination
        return redirect(url_for('auth.dashboard')) 

@auth_bp.route('/view_entry/<int:entry_id>', methods=['GET'])
@login_required
def view_entry(entry_id):
    entry = JournalEntry.query.get_or_404(entry_id)
    if entry.author_id != current_user.id:
        abort(404)  # Or handle the case where the entry is not found or doesn't belong to the current user
    return render_template(
        'view_entry.html', 
        entry=entry, 
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='user-all-entries',
        user_tags=current_user.tags
    )

@auth_bp.route('/edit_entry', methods=['POST'])
@login_required
def edit_entry():
    # Get the data
    journal_entry_id = request.form['journal_entry_id']

    # Get the JournalEntry by ID
    journal_entry = JournalEntry.query.get_or_404(journal_entry_id)

    # Make sure that the current_user is the author of this journal entry
    if not journal_entry.author_id == current_user.id:
        abort(403)

    entry_title:str = request.form['title']
    entry_content:str = request.form['content']
    entry_tags:list =  [tag.strip() for tag in request.form['tags'].split(',') if tag.strip()]
    # Check if the locked field is present in the form data
    entry_locked = request.form.get('locked')
    if entry_locked:
        # Convert 'on' to True if the checkbox is checked
        entry_locked = True
    else:
        # If the checkbox is not checked, set it to False
        entry_locked = False

    # Make the journal_entry json
    entry_data = {
        "title": entry_title,
        "content": entry_content,
        "tags": entry_tags,
        "locked": entry_locked
    }

    # Make a PUT request to the API endpoint
    api_url = current_app.config['HOST'] + f'/api/journal_entries/{journal_entry_id}'
    headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
    response = requests.put(api_url, json=entry_data, headers=headers)

    # Check the response status code and flash messages accordingly
    if response.status_code == 200:
        logger.info("JournalEntry updated by `{current_user.username}`.")
        flash('Journal entry updated successfully!', 'success')
        
    else:
        logger.error(f"`{current_user.username}` tried to update journal entry but error occurred.")
        flash('Failed to update journal entry. Please try again later.', 'error')
        
    
    # If the user is authorized, redirect to the route
    return redirect(url_for('auth.view_entry', entry_id=journal_entry_id))


@auth_bp.route('/update_tag', methods=['POST'])
@login_required
def update_tag():
    # Get the tag_id
    tag_id = request.form.get('tag_id')

    # Get the Tag by ID
    tag = Tag.query.get_or_404(tag_id)

    # Make sure that the current_user is the creator of this journal entry
    if not tag.creator_id == current_user.id:
        abort(403)

    # Get the data
    tag_name = Tag.preprocess_tag_name(request.form.get('name'))
    description = request.form.get('description')
    color_hex = request.form.get('color_hex')
    color_red, color_green, color_blue = Tag.hex_to_rgb(color_hex)

    tag_data = {
        "name": tag_name,
        "description": description,
        "color_red": color_red,
        "color_green": color_green,
        "color_blue": color_blue
    }
  
    # Make a PUT request to the API endpoint
    api_url = current_app.config['HOST'] + f'/api/tags/{tag_id}'
    headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
    response = requests.put(api_url, json=tag_data, headers=headers)

    # Check the response status code and flash messages accordingly
    if response.status_code == 200:
        logger.info("Tag updated by `{current_user.username}`.")
        flash('Tag updated successfully!', 'success')
        
    else:
        logger.error(f"`{current_user.username}` tried to update a Tag but error occurred.")
        flash('Failed to update the Tag. Please try again later.', 'error')
    
    # If the user is authorized, redirect to the route
    return redirect(url_for('auth.manage_tags', user_id=current_user.id))


# Route to handle the POST request to delete a JournalEntry
@auth_bp.route('/delete_entry/<destination>', methods=['POST'])
@login_required
def delete_entry(destination):
    password = request.form.get('password')
    journal_entry_id = request.form['journal_entry_id']

    if not current_user.check_password(password):
        # If the password is not correct, then don't delete the entry
        flash('Incorrect password. Please try again.', 'error')
    else:
        # Make DELETE request to the api
        api_endpoint = f"{current_app.config['HOST']}/api/journal_entries/{journal_entry_id}"
        response = requests.delete(
            api_endpoint,
            headers={'Authorization': f"Bearer {current_app.config['SECRET_API_TOKEN']}"}
        )
        if response.status_code == 200:
            logger.info(f"JournalEntry deleted successfully by {current_user.username}!")
            flash(f"JournalEntry deleted successfully by {current_user.username}!", "success")
        else:
            logger.error(f"An error occurred while deleting the JournalEntry with ID {journal_entry_id}.")
            flash("An error occurred during JournalEntry deletion. Please try again.", 'error')
    
    # Redirect to the specified destination
    if destination == 'dashboard':
        return redirect(url_for('auth.dashboard'))
    elif destination == 'profile':
        return redirect(url_for('auth.profile'))
    elif destination == 'user-all-entries':
        return redirect(url_for('auth.user_journal_entries', user_id=current_user.id))
    else:
        # Handle invalid destination
        return redirect(url_for('auth.dashboard')) 


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
                subject=f"{current_app.config['FLASK_APP_NAME']}: New Account Registration",
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
        api_user_post_url = current_app.config['HOST'] + '/api/create/user'
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

