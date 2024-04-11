# app/auth/routes.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import render_template, url_for, flash, redirect, current_app, request, session, abort, jsonify, send_file
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
from app.utils.encryption import generate_derived_key_from_passwd, decrypt_user_private_key, encrypt, decrypt
from scripts.utils import count_words, convert_utc_to_ist_str, format_years_ago
from config import EmailConfig

import logging
import json
from datetime import datetime
import requests
from cryptography.fernet import InvalidToken 

from . import auth_bp

logger = logging.getLogger(__name__)

def redirect_to_destination(destination):
    # Redirect to the specified destination
    if destination == 'dashboard':
        return redirect(url_for('auth.dashboard'))
    elif destination == 'profile':
        return redirect(url_for('auth.profile'))
    elif destination == 'user-all-entries':
        return redirect(url_for('auth.user_journal_entries', user_id=current_user.id))
    elif destination == 'search':
        return redirect(url_for('auth.search', user_id=current_user.id))
    elif destination == 'favourites':
        return redirect(url_for('auth.favourites', user_id=current_user.id))
    else:
        # Handle invalid destination
        return redirect(url_for('auth.dashboard')) 

@auth_bp.before_request
def update_last_seen():
    if current_user.is_authenticated:
        user_id = current_user.id
        api_url = current_app.config['HOST'] + f'/api/users/{user_id}/update_last_seen'
        headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
        
        try:
            response = requests.post(api_url, headers=headers)
            if response.status_code != 200:
                logger.error(f"POST request to {api_url} failed with status code {response.status_code}")
        except Exception as e:
            logger.exception(f"An error occurred while making a POST request to {api_url}: {e}")


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
                # Save the User's derived key to the session 
                derived_key = generate_derived_key_from_passwd(form.passwd.data)
                user_private_key = decrypt_user_private_key(
                    encrypted_private_key=current_user.encrypted_private_key,
                    derived_key=derived_key
                )
                session['current_user_private_key'] = user_private_key
                
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

    # Get the current user's private key from session
    private_key = session['current_user_private_key']


    return render_template(
        'dashboard.html', 
        user=user,
        user_journal_entries = user_journal_entries,
        onthis_day_journal=onthis_day_journal,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        format_years_ago=format_years_ago,
        redirect_destination='dashboard',
        decrypt=decrypt,
        private_key=private_key
    )


@auth_bp.route('/users/<int:user_id>/journal_entries')
@login_required
def user_journal_entries(user_id):
    # Check if the current user's ID matches the provided user_id
    if current_user.id != user_id:
        abort(403)  # Forbidden - Current user does not have access to view another user's journal entries

    # Get the current user's private key from session
    private_key = session['current_user_private_key']

    # Get the current user's journal entries and tags
    user_portfolio = current_user.portfolio(private_key)

    # Count the total number of journal entries, tags, and words
    total_journal_entries = user_portfolio['total_journal_entries']
    total_tags = user_portfolio['total_tags']
    total_words_in_journal_entries = user_portfolio['total_words']

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
        total_words_in_journal_entries=total_words_in_journal_entries,
        decrypt=decrypt,
        private_key=private_key
    )


@auth_bp.route('/favourites/<int:user_id>', methods=['GET'])
@login_required
def favourites(user_id):
    if user_id != current_user.id:
        abort(404)

    # Get the current user's private key from session
    private_key = session['current_user_private_key']

    favourite_journal_entries = JournalEntry.query.filter(
        (JournalEntry.author_id == current_user.id) &
        (JournalEntry.favourite == True)
    ).all()


    return render_template(
        'favourites.html', 
        user_journal_entries=favourite_journal_entries,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='favourites',
        private_key=private_key,
        decrypt=decrypt
    )

@auth_bp.route('/profile')
@login_required
def profile():

    # Get the current user's private key from session
    private_key = session['current_user_private_key']

    # Get the current user's portfolio
    user_portfolio = current_user.portfolio(private_key)

    # Count the total number of journal entries, tags, and words
    total_journal_entries = user_portfolio['total_journal_entries']
    total_tags = user_portfolio['total_tags']
    total_words_in_journal_entries = user_portfolio['total_words']

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
        redirect_destination='profile',
        decrypt=decrypt,
        private_key=private_key
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

    return redirect_to_destination(destination)


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

    return redirect_to_destination(destination)
    
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

        # Encrypt the journal_entry title and content
        # Get the current_user's private key from session
        user_private_key = session['current_user_private_key']

        # Encrypt the JournalEntry title and content
        _title = encrypt(data=form.title.data, key=user_private_key)
        _content = encrypt(data=form.content.data, key=user_private_key)

        # Create a json body for the api request
        entry_json = {
            "title": _title,
            "content": _content,
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

    return redirect_to_destination(destination)
    

# Route to toggle the is_admin value
@auth_bp.route('/toggle_entry_favourite', methods=['POST'])
@login_required
def toggle_entry_favourite():
    # Get the password and `journal_entry_id` from the form
    journal_entry_id  = request.form.get('journal_entry_id')
    destination = request.form.get('destination')

    # Get the JournalEntry by ID
    journal_entry = JournalEntry.query.get_or_404(journal_entry_id)

    # Make sure that the current_user is the author of this journal entry
    if not journal_entry.author_id == current_user.id:
        abort(403)

    # Toggle the favourite attribute of the journal_entry
    payload = {"favourite": not journal_entry.favourite}

    # Make PUT request to the endpoint 
    api_endpoint = f"{current_app.config['HOST']}/api/journal_entries/{journal_entry_id}"
    response = requests.put(
        api_endpoint,
        headers={'Authorization': f"Bearer {current_app.config['SECRET_API_TOKEN']}"},
        json=payload
    )
        
    if response.status_code == 200:
        logger.info(f"`{current_user.username}` changed the `favourite` status of one of their JournalEntry.")
        flash("The 'favourite' status of the JournalEntry has been updated!", 'success')
    else:
        logger.error(f"Failed to update journal entry favourite status. Status code: {response.status_code}\n{response.text}")
        flash(f"API_ERROR: Failed to update journal entry favourite status. Status code: {response.status_code}", 'error')

    return redirect_to_destination(destination)

@auth_bp.route('/view_entry/<int:entry_id>', methods=['GET'])
@login_required
def view_entry(entry_id):
    entry = JournalEntry.query.get_or_404(entry_id)
    if entry.author_id != current_user.id:
        abort(404)

    # Get the current user's private key from session
    private_key = session['current_user_private_key']

    return render_template(
        'view_entry.html', 
        entry=entry, 
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='user-all-entries',
        user_tags=current_user.tags,
        private_key=private_key,
        decrypt=decrypt
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

    # Get the current_user's private_key from session
    user_private_key = session['current_user_private_key']

    # Encrypt the JournalEntry title and content
    _title = encrypt(data=entry_title, key=user_private_key)
    _content = encrypt(data=entry_content, key=user_private_key)

    # Make the journal_entry json
    entry_data = {
        "title": _title,
        "content": _content,
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
        logger.error(f"`{current_user.username}` tried to update journal entry but error occurred\n{response.content}.")
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
        "description": description,
        "color_red": color_red,
        "color_green": color_green,
        "color_blue": color_blue
    }

    # Check whether the user has changed the tag name
    tag_data["name"] = None if tag_name == tag.name else tag_name
  
    # Make a PUT request to the API endpoint
    api_url = current_app.config['HOST'] + f'/api/tags/{tag_id}'
    headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
    response = requests.put(api_url, json=tag_data, headers=headers)

    # Check the response status code and flash messages accordingly
    if response.status_code == 200:
        logger.info("Tag updated by `{current_user.username}`.")
        flash('Tag updated successfully!', 'success')
        
    else:
        logger.error(f"`{current_user.username}` tried to update a Tag but error occurred. Response content: {response.content}")
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
            flash(f"JournalEntry deleted successfully!", "success")
        else:
            logger.error(f"An error occurred while deleting the JournalEntry with ID {journal_entry_id}.")
            flash("An error occurred during JournalEntry deletion. Please try again.", 'error')
    
    return redirect_to_destination(destination)


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

            # Derive the password reset key
            passwd_reset_key = generate_derived_key_from_passwd(new_user_data['password'])

            # Send welcome email to the user with the new password_reset_key.
            _email_html_text = render_template(
                'emails/welcome_email.html',
                passwd_reset_key=passwd_reset_key.hex(), # To reverse this use bytes.fromhex(password_reset_key_hex)
                username=new_user_data['fullname']
            )

            msg = EmailMessage(
                sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                to=new_user_data['email'],
                subject="Welcome to MindCanvas!",
                email_html_text=_email_html_text
            )

            try:
                msg.send(
                    sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                    server_info=EmailConfig.GMAIL_SERVER,
                    print_success_status=False
                )

                flash('A welcome email containing a password reset key has been dispatched to your email address.', 'info')
                logger.info(f"EMAIL_SENT: Welcome email with password reset key has been emailed to 'new_user_data['fullname']'.")

            except Exception as e:
                # TODO: Handle email sending error better
                flash('An error occurred while attempting to send the welcome email. Try again!', 'danger')
                logger.error(f"Error occurred while attempting to send welcome email along with password reset key through email.\nERROR: {e}")

            return redirect(url_for('auth.login'))
        else:
            logger.error("Failed to register the user.")
            flash('Failed to register user. Please try again.', 'danger')

    return render_template('register_user.html', form=form, user_data=user_data)


@auth_bp.route('/search/<int:user_id>', methods=['GET', 'POST'])
@login_required
def search(user_id):
    # Initialize empty list for search results
    search_results = []
    query = "Search ..."

    # Check if the current user is authorized to access the search functionality
    if not current_user.id == user_id:
        abort(403)

    # Process the search query if the request method is POST
    if request.method == 'POST':
        # Get the search query from the form
        query = request.form.get('q')
        private_key = session['current_user_private_key']

        search_results = JournalEntry.query.filter_by(author_id=user_id).all()

        # Decrypt titles and contents before filtering
        for entry in search_results:
            entry.title = decrypt(entry.title, private_key)
            entry.content = decrypt(entry.content, private_key)

        # Filter decrypted titles and contents for the search query
        search_results = [
            entry 
            for entry in search_results 
            if query in entry.title 
            or query in entry.content
        ]

    # Render the search.html template with necessary data
    return render_template(
        'search.html', 
        user_id=current_user.id, 
        search_results=search_results,
        query= query,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='search'  # Additional context for the template
    )

# A route for export data
@auth_bp.route('/export_data', methods=['POST'])
@login_required
def export_data():
    try:
        # Get the private_key and user_id
        json_data = {
            "user_id": current_user.id,
            "private_key": session.get('current_user_private_key')
        }

        # Make a GET request to the API endpoint
        api_url = current_app.config['HOST'] + '/api/mindcanvas/export'  # Replace with your actual API URL
        response = requests.get(
            api_url,
            json=json_data
        )

        # Check if request was successful
        if response.status_code != 200:
            print(response.content)
            return jsonify({'message': 'Failed to fetch data from API'}), 500

        # Convert API response to JSON
        data = response.json()

        # Generate file name with current datetime
        current_datetime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        file_name = f"mindcanvas_{current_user.username}_data_{current_datetime}.json"

        # If the app_data dir is not created create it 
        app_data_dir = current_app.config['APP_DATA_DIR']
        # Create the directory if it doesn't exist
        app_data_dir.mkdir(parents=True, exist_ok=True)

        file_path = app_data_dir / f'{file_name}'

        # Create a JSON file
        with open(file_path, 'w') as file:
            json.dump(data, file, indent=4)

        # flash message
        flash(
            "A JSON file containing all your MindCanvas data has been downloaded in an unencrypted format. Please ensure to keep it safe. This file can be used to import all of your data back into MindCanvas at any time.",
            'success'
        )
        
        # Prepare file for download
        return send_file(file_path, as_attachment=True)

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@auth_bp.route('/import_data', methods=['GET', 'POST'])
@login_required
def import_data():
    if request.method == 'POST':
        try:
            json_file = request.files['jsonFile']

            if json_file.filename == '':
                return render_template('import_data.html', message='No file selected.')

            if json_file and json_file.filename.endswith('.json'):
                # Load JSON data from the file
                data = json_file.read().decode('utf-8')
                json_data = json.loads(data)

                # Include private key and current_user id in JSON payload
                json_data['private_key'] = session.get('current_user_private_key')
                json_data['user_id'] = current_user.id

                # Make a POST request to the API endpoint with the JSON data
                api_user_post_url = current_app.config['HOST'] + '/api/mindcanvas/import'
                
                response = requests.post(
                    api_user_post_url, 
                    json=json_data
                )

                if response.status_code == 200:
                    return render_template('import_data.html', message='Data imported successfully.')
                else:
                    return render_template('import_data.html', message=f'Failed to import data. Please try again later.\n{response.content}')

            else:
                return render_template('import_data.html', message='Invalid file format. Please select a JSON file.')

        except Exception as e:
            return render_template('import_data.html', message=f'Error: {str(e)}')

    return render_template('import_data.html')


@auth_bp.route('/update_profile', methods=['POST'])
@login_required
def update_profile():

    # Get the user data
    _fullname = request.form.get('fullname')
    _username = request.form.get('username')
    _email = request.form.get('email')
    _password = request.form.get('password')
    _user_id = request.form.get('user_id')

    # Get the user
    user = User.query.get_or_404(_user_id)

    if user.check_password(_password):
        # Correct password provided
        json_body = {}

        # Check whether the `_email` is different! If different then send email
        # to verify email.
        _send_email_verification = False
        if user.email != _email:
            # Check if email is already taken
            existing_user = User.query.filter_by(email=_email).first()
            if existing_user:
                # Email is already taken
                flash('Email is already taken. Please choose a different email.', 'error')
                return redirect(url_for('auth.profile'))

            # Add the email to the request body
            json_body['email'] = _email

            _send_email_verification = True
        
        if user.username != _username:
            # Check if username is already taken
            existing_user2 = User.query.filter_by(email=_username).first()
            if existing_user2:
                # Email is already taken
                flash('Username is already taken. Please choose a different username.', 'error')
                return redirect(url_for('auth.profile'))
            
            # Add the username to the request body
            json_body['username'] = _username

        # Add the fullname to the request body
        json_body['fullname'] = _fullname

        # Make a PUT request to the API
        api_endpoint = current_app.config['HOST'] + f'/api/users/{user.id}'
        headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
        response = requests.put(
            api_endpoint,
            json=json_body,
            headers=headers
        )

        if response.status_code == 200:
            msg = (
                f"Your profile has been updated successfully. Please verify your new email address by visiting your profile."
                if _send_email_verification
                else
                "Your profile has been updated successfully."
            )
            flash(msg, 'success')
            logger.info(f"Profile updated successfully: {user.username}.")

        else:
            flash(f"Error occurred while updating the profile. Try again later!", 'error')
            logger.error(f"An error occurred while editing user profile: {user.username}.\nERROR: {response.content}")
    else:
        flash("Wrong password!", 'error')

    return redirect(url_for('auth.profile'))


@auth_bp.route('/send_verification_email', methods=['GET'])
@login_required
def send_verification_email():
    if not current_user.email_verified:
        # Generate verification token
        token = current_user.generate_email_verification_token()

        # Construct verification link
        verification_link = url_for('auth.verify_email', token=token, _external=True)

        _email_html_text = render_template(
            'emails/email_verification.html',
            verification_link=verification_link
        )

        msg = EmailMessage(
            sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
            to=current_user.email,
            subject=f"{current_app.config['FLASK_APP_NAME']}: Email verification!",
            email_html_text=_email_html_text
        )

        try:
            msg.send(
                sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                server_info=EmailConfig.GMAIL_SERVER,
                print_success_status=False
            )

            flash('Email verification link sent to your email address. Please check and follow the link.', 'info')
            logger.info(f"Email verification link sent over email to '{current_user.email}'.")
            
            return redirect(url_for('auth.profile'))
            
        except Exception as e:
            # TODO: Handle email sending error better
            flash('An error occurred while attempting to send the email verification link through email. Try again!', 'danger')
            logger.error(f"Error occurred while attempting to send the email verification link through email.\nERROR: {e}")
            return redirect(url_for('auth.profile'))
    
    return redirect(url_for('auth.profile'))


@auth_bp.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user = User.verify_email_verification_token(token)
    if user:
        # Make a PUT request to the API
        api_endpoint = current_app.config['HOST'] + f'/api/users/{user.id}'
        headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
        response = requests.put(
            api_endpoint,
            json={"email_verified": True},
            headers=headers
        )

        if response.status_code == 200:
            flash('Your email has been successfully verified!', 'success')
            logger.info(f"Email verified successfully: '{user.username}'")
        else:
            flash("Email cannot be verified due to some error. Try again later!", 'error')
            logger.error(f"Error occurred while verifying email address.\nERROR: {response.content}")

    else:
        flash('Invalid or expired verification link. Please try again.', 'error')

    return redirect(url_for('auth.login'))


@auth_bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user_id = request.form.get('user_id')
    old_passwd = request.form.get('old_passwd')

    if current_user.id != int(user_id):
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.check_password(old_passwd):
        new_passwd = request.form.get('new_passwd')
        confirm_passwd = request.form.get('confirm_passwd')

        if new_passwd != confirm_passwd:
            flash("Passwords didn't match. Try again!", 'error')
            return redirect(url_for('auth.profile'))
        
        # Get user's private key from the session
        user_private_key = session['current_user_private_key']

        # Make POST request to the API
        api_endpoint = current_app.config['HOST'] + f'/api/users/{user.id}/change_password'
        headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
        response = requests.post(
            api_endpoint,
            json={
                "new_password": new_passwd,
                "private_key": user_private_key
            },
            headers=headers
        )

        if response.status_code == 200:
            flash("Password changed successfully.", 'success')
            logger.info(f"PASSWORD_CHANGE: The user '{user.username}' changed their password.")

            # Derive the password reset key
            passwd_reset_key = generate_derived_key_from_passwd(new_passwd)

            # Send email to the user with the new password_reset_key.
            _email_html_text = render_template(
                'emails/change_passwd_email.html',
                passwd_reset_key=passwd_reset_key.hex(), # To reverse this use bytes.fromhex(password_reset_key_hex)
                username=user.fullname
            )

            msg = EmailMessage(
                sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                to=current_user.email,
                subject=f"{current_app.config['FLASK_APP_NAME']}: Password Change Notification!",
                email_html_text=_email_html_text
            )

            try:
                msg.send(
                    sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                    server_info=EmailConfig.GMAIL_SERVER,
                    print_success_status=False
                )

                flash('An email containing a password reset key has been dispatched to your email address.', 'info')
                logger.info(f"EMAIL_SENT: A password change notification with password reset key has been emailed to '{current_user.email}'.")

            except Exception as e:
                # TODO: Handle email sending error better
                flash('An error occurred while attempting to send the password reset key through email. Try again!', 'danger')
                logger.error(f"Error occurred while attempting to send the password change notification along with password reset key through email.\nERROR: {e}")
        else:
            flash("Error occurred while changing the password.", 'error')
            logger.error(f"API_ERROR: couldn't change the user password due to err during api call.\n{response.content}")
    else:
        flash("Wrong old password!", 'error')

    return redirect(url_for('auth.profile'))

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':
        username_email = request.form.get('username_email')
        passwd_reset_key = request.form.get('passwd_reset_key')
        new_passwd = request.form.get('new_passwd')
        confirm_passwd = request.form.get('confirm_passwd')

        # Get the user
        user = User.query.filter((User.username == username_email) | (User.email == username_email)).first()
        
        if user:
            
            if not new_passwd == confirm_passwd:
                flash("Passwords don't match. Try again!", 'error')
                return render_template('forgot_password.html')
            
            try:
                # Get user's encrypted_private_key
                user_encrypted_private_key = user.encrypted_private_key

                # Make the derived key from the passwd_reset_key
                user_derived_key = bytes.fromhex(passwd_reset_key)

                # Decrypt user's encrypted private key
                user_private_key = decrypt_user_private_key(
                    user_encrypted_private_key,
                    user_derived_key
                )

                # Make POST request to the API
                api_endpoint = current_app.config['HOST'] + f'/api/users/{user.id}/change_password'
                headers = {'Authorization': 'Bearer ' + current_app.config['SECRET_API_TOKEN']}
                response = requests.post(
                    api_endpoint,
                    json={
                        "new_password": new_passwd,
                        "private_key": user_private_key
                    },
                    headers=headers
                )

                if response.status_code == 200:
                    flash("Your password has been successfully changed. You can now log in using your new password.", 'success')
                    logger.info(f"PASSWORD_CHANGE: The user '{user.username}' changed their password.")

                    # Derive the password reset key
                    passwd_reset_key = generate_derived_key_from_passwd(new_passwd)

                    # Send email to the user with the new password_reset_key.
                    _email_html_text = render_template(
                        'emails/change_passwd_email.html',
                        passwd_reset_key=passwd_reset_key.hex(),
                        username=user.fullname
                    )

                    msg = EmailMessage(
                        sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                        to=user.email,
                        subject=f"{current_app.config['FLASK_APP_NAME']}: Password Reset Successful!",
                        email_html_text=_email_html_text
                    )

                    try:
                        msg.send(
                            sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                            server_info=EmailConfig.GMAIL_SERVER,
                            print_success_status=False
                        )

                        flash('An email containing a password reset key has been dispatched to your email address.', 'info')
                        logger.info(f"EMAIL_SENT: A password reset notification with password reset key has been emailed to '{user.email}'.")
                        return redirect(url_for('auth.login'))
                    
                    except Exception as e:
                        # TODO: Handle email sending error better
                        flash('An error occurred while attempting to send the password reset key through email. Try again!', 'danger')
                        logger.error(f"Error occurred while attempting to send the password change notification along with password reset key through email.\nERROR: {e}")

            except ValueError:
                flash("Invalid password reset key. Please enter a valid key.", 'error')
            except InvalidToken:
                flash("Invalid token. Please check your password reset key and try again.", "error")
            except Exception as e:
                flash(f"An error occurred: {str(e)}", 'error')
                logger.error(f"An error occurred while resetting the user's password.\n{e}")
                
        else:
            flash(f"Sorry, we couldn't find any user with the username or email '{username_email}'.", 'error')

    return render_template('forgot_password.html')


from flask import flash

@auth_bp.route('/user/<int:user_id>/journal_entries/tag/<int:tag_id>', methods=['GET'])
@login_required
def get_journal_entries_by_tag(user_id, tag_id):
    # Find the user by user_id
    user = User.query.get_or_404(user_id)

    # Ensure the tag belongs to the user
    tag = Tag.query.filter_by(id=tag_id, creator_id=user_id).first()
    if not tag:
        abort(404)

    # Query journal entries associated with the tag for the user
    journal_entries = JournalEntry.query.join(JournalEntry.tags).filter_by(id=tag_id, creator_id=user_id).all()

    # Get user's private key
    private_key = session['current_user_private_key']

    return render_template(
        'journal_entries_by_tag.html', 
        user=user, 
        tag=tag, 
        user_journal_entries=journal_entries,
        decrypt=decrypt,
        private_key=private_key,
        convert_utc_to_ist_str=convert_utc_to_ist_str
    )
