# Standard library imports
import json
import logging
import os
from datetime import datetime
from math import ceil

# Third-party imports
from flask import abort, current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import desc, extract
from cryptography.fernet import InvalidToken

# Local application imports
from app.forms.auth_forms import EmailRegistrationForm, UserLoginForm, UserRegistrationForm
from app.forms.user_forms import AddEntryForm, CreateNewTagForm
from app.models.journal_entry import JournalEntry
from app.models.tag import Tag
from app.models.user import User
from app.utils.decorators import logout_required
from app.utils.encryption import decrypt, decrypt_user_private_key, generate_derived_key_from_passwd
from app.utils.journal_utils import create_journal_entry, delete_journal_entry, update_existing_journal_entry
from app.utils.tag_utils import create_user_tag, delete_existing_tag, update_existing_tag
from app.utils.token import get_token_for_email_registration, confirm_email_registration_token
from app.utils.user_utils import update_user_last_seen, create_new_user, export_user_data, import_user_data, update_user, change_user_password
from config import EmailConfig
from scripts.email_message import EmailMessage
from scripts.utils import convert_utc_to_ist_str, format_years_ago, sha256_hash

# Relative imports
from . import auth_bp
from .routes import redirect_to_destination

logger = logging.getLogger(__name__)


@auth_bp.route('/users/<int:user_id>/create_tag', methods=['GET', 'POST'])
@login_required
def create_tag(user_id):
    # Check if the current user is authorized to add an entry for the specified user
    if current_user.id != user_id:
        abort(403)  # Forbidden

    form = CreateNewTagForm()

    # Tags those are already created by the current_user
    user_tags = current_user.tags

    # User's private key from session
    user_private_key = session['current_user_private_key']

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

        if sha256_hash(tag_name) in [t.name_hash for t in user_tags]:
            # Redirect
            form.name.data = tag_name
            form.description.data = description
            form.color_red.data = color_red
            form.color_green.data = color_green
            form.color_blue.data = color_blue

            flash(f"The name '{tag_name}' is already in your tag list!", 'info')
            return render_template('create_tag.html', form=form, user_tags=user_tags, decrypt=decrypt, private_key=user_private_key)


        # Create the tag
        status_code, message = create_user_tag(**tag_data, private_key=user_private_key)

        # Check the response status code and flash messages accordingly
        if status_code == 201:
            flash(f"Your tag '{tag_name}' has been added successfully!", 'success')
            logger.info(f"A new Tag, '{tag_name}' is added by `{current_user.username}`.")
            
            # Redirect to manage_tags
            return redirect(url_for('auth.manage_tags', user_id=current_user.id))
        elif status_code == 400:
            flash(f"A tag with name '{tag_name}' already exists!", 'info')

            # Redirect to manage_tags
            return redirect(url_for('auth.manage_tags', user_id=current_user.id))
        else:
            flash('Failed to create the new tag. Please try again later.', 'error')
            logger.error(f"`{current_user.username}` tried to add a new JournalEntry but error occurred.\nError: {message}")

        # Remove the user data
        form = CreateNewTagForm(formdata=None)

    # Render the add entry form template
    return render_template('create_tag.html', form=form, user_tags=user_tags, decrypt=decrypt, private_key=user_private_key)


@auth_bp.route('/update_tag', methods=['POST'])
@login_required
def update_tag():
    # Get the tag_id
    tag_id = request.form.get('tag_id')

    # Get the Tag by ID
    tag = Tag.query.get_or_404(tag_id)

    # Get current user's private_key from session
    user_private_key = session['current_user_private_key']

    # Make sure that the current_user is the creator of this journal entry
    if not tag.creator_id == current_user.id:
        abort(403)

    # Get the data
    tag_name = Tag.preprocess_tag_name(request.form.get('name'))
    description = request.form.get('description')
    color_hex = request.form.get('color_hex')
    color_red, color_green, color_blue = Tag.hex_to_rgb(color_hex)

    tag_data = {
        "tag_id": tag.id,
        "description": description,
        "color_red": color_red,
        "color_green": color_green,
        "color_blue": color_blue
    }

    # Check whether the user has changed the tag name
    tag_data["name"] = None if sha256_hash(tag_name) == tag.name_hash else tag_name
  
    # Update tag!
    status_code, message = update_existing_tag(**tag_data, private_key=user_private_key)

    # Check the response status code and flash messages accordingly
    if status_code == 200:
        logger.info(f"Tag updated by `{current_user.username}`.")
        flash('Tag updated successfully!', 'success')
    elif status_code == 400:
        logger.error(f"Error occurred while updating tag. ERROR {message['message']}")
        flash(message=message['message'], category='error')
        
    else:
        logger.error(f"`{current_user.username}` tried to update a Tag but error occurred. Response content: {message}")
        flash('Failed to update the Tag. Please try again later.', 'error')
    
    # If the user is authorized, redirect to the route
    return redirect(url_for('auth.manage_tags', user_id=current_user.id))


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
        # Delete the tag
        status_code, message = delete_existing_tag(tag_id=tag_id)
        if status_code == 200:
            logger.info(f"Tag deleted successfully by {current_user.username}!")
            flash(f"Tag deleted successfully!", "success")
        else:
            logger.error(f"An error occurred while deleting the Tag with ID {tag_id}.\nError: {message}")
            flash("An error occurred during Tag deletion. Please try again.", 'error')
    
    return redirect(url_for('auth.manage_tags', user_id=current_user.id))

    
@auth_bp.route('/users/<int:user_id>/manage_tags')
@login_required
def manage_tags(user_id):
    # Check if the current user's ID matches the provided user_id
    if current_user.id != user_id:
        abort(403)  # Forbidden - Current user does not have access to view another user's journal entries

    # Get the current user's tags
    user_tags = current_user.tags

    # User's private key from session
    user_private_key = session['current_user_private_key']

    # Count the total number of journal entries, tags, and words
    total_tags = len(user_tags)

    return render_template(
        'manage_tags.html',
        user_tags=user_tags,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        decrypt=decrypt,
        private_key=user_private_key
    )