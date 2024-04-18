# app/admin/routes.py
# Author: Indrajit Ghosh
# Created On: Feb 02, 2024
#
from flask import render_template, url_for, flash, redirect, request, current_app
from flask_login import current_user
from sqlalchemy import desc

from app.models.user import User
from app.utils.decorators import admin_required
from app.utils.user_utils import delete_user_from_db
from scripts.utils import convert_utc_to_ist_str

import logging

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

    # Delete the user!
    status_code, message = delete_user_from_db(user_id=user_id)
    if status_code == 200:
        logger.info(f"A user has been deleted by the administrator: `{current_user.username}`")
        flash("User deleted successfully!", "success")
    else:
        logger.error(f"An error occurred while deleting the user with ID {user_id}. Admin: `{current_user.username}`.\nERROR: {message['message']}")
        flash("An error occurred during user deletion. Please try again.", 'error')
    return redirect(url_for('admin.home'))
