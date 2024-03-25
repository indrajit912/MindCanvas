# app/admin/routes.py
# Author: Indrajit Ghosh
# Created On: Feb 02, 2024
#
from flask import render_template, url_for, flash, redirect, request, current_app
from flask_login import login_user, login_required, current_user, logout_user
from sqlalchemy import desc

from app.models.models import User, JournalEntry, Tag
from app.utils.decorators import admin_required
from config import EmailConfig
from scripts.utils import convert_utc_to_ist

from datetime import datetime
import logging
import requests

from . import admin_bp

logger = logging.getLogger(__name__)

@admin_bp.route('/')
def home():
    # Retrieve all users and monitored ads from the database
    users = User.query.order_by(desc(User.date_joined)).all()

    # User api url
    user_api_url = current_app.config['HOST'] + '/api/users'
        
    # logger.info(f"Admin dashboard visited by the admin '{current_user.email}'.")

    return render_template(
        'admin.html', 
        users=users,
        convert_utc_to_ist=convert_utc_to_ist,
        user_api_url=user_api_url
    )

# Route to toggle the is_admin value
@admin_bp.route('/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    # Ensure the current user has admin privileges
    if not current_user.email == EmailConfig.INDRAJIT912_GMAIL:
        flash('You do not have permission to perform this action.', 'danger')
        logger.warning(f"The user '{current_user.email}' tried to toggle admin status!")
        return redirect(url_for('auth.dashboard'))

    
    # Send PUT request to the api
    api_user_post_url = current_app.config['HOST'] + '/api/users'
    response = requests.post(api_user_post_url, json={})

    if response.status_code == 201:
        flash('User registered successfully!', 'success')
        return redirect(url_for('auth.login'))
    else:
        flash('Failed to register user. Please try again.', 'danger')


    

