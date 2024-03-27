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
from scripts.utils import convert_utc_to_ist_str

from datetime import datetime
import logging
import requests

from . import admin_bp

logger = logging.getLogger(__name__)

@admin_bp.route('/')
@admin_required
def home():
    # Retrieve all users and monitored ads from the database
    users = User.query.order_by(desc(User.date_joined)).all()

    logger.info(f"Admin dashboard visited by the admin '{current_user.email}'.")

    return render_template(
        'admin.html', 
        users=users,
        convert_utc_to_ist_str=convert_utc_to_ist_str
    )


# Route to handle the POST request to delete the user
@admin_bp.route('/delete_user', methods=['POST'])
@admin_required
def delete_user():
    user_id = request.form['user_id']  # Assuming user_id is sent as form data

    # Make DELETE request to the api
    api_endpoint = f"{current_app.config['HOST']}/api/user/{user_id}"
    response = requests.delete(
        api_endpoint,
        headers={'Authorization': f"Bearer {current_app.config['SECRET_API_TOKEN']}"}
    )
    if response.status_code == 200:
        flash("User deleted successfully!", "success")
    else:
        flash("Error occurred while deletion. Try again", 'error')
    return redirect(url_for('admin.home'))