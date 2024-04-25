# Standard library imports
import json
import logging
import os
from datetime import datetime
from math import ceil

# Third-party imports
from flask import current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_login import current_user, login_required
from sqlalchemy import desc, extract

# Local application imports
from app.models.journal_entry import JournalEntry
from app.models.user import User
from app.utils.encryption import decrypt
from app.utils.user_utils import export_user_data, import_user_data, update_user
from config import EmailConfig
from scripts.email_message import EmailMessage
from scripts.utils import convert_utc_to_ist_str, format_years_ago

# Relative imports
from . import auth_bp

logger = logging.getLogger(__name__)


@auth_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = current_user

    # Get the page number from the request or default to the first page
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Last 10 journal Entries
    user_journal_entries = JournalEntry.query.filter_by(
        author_id=current_user.id
    ).order_by(
        desc(JournalEntry.last_updated)
    ).limit(3).all()

    # Paginate the entries manually
    total_entries = len(user_journal_entries)
    total_pages = ceil(total_entries / per_page)
    start_index = (page - 1) * per_page
    end_index = min(start_index + per_page, total_entries)
    paginated_entries = user_journal_entries[start_index:end_index]


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
        pagination={},
        user_journal_entries=paginated_entries,
        onthis_day_journal=onthis_day_journal,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        format_years_ago=format_years_ago,
        redirect_destination='dashboard',
        decrypt=decrypt,
        private_key=private_key
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

    # Get the page number from the request or default to the first page
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Query the database for the last five journal entries of the current user
    user_journal_entries = JournalEntry.query.filter_by(
        author_id=current_user.id
    ).order_by(
        JournalEntry.date_created.desc()
    ).limit(3).all()

    # Paginate the entries manually
    total_entries = len(user_journal_entries)
    total_pages = ceil(total_entries / per_page)
    start_index = (page - 1) * per_page
    end_index = min(start_index + per_page, total_entries)
    paginated_entries = user_journal_entries[start_index:end_index]

    
    # Pass the count_words function to the template
    return render_template(
        'profile.html',
        user=current_user, 
        total_journal_entries=total_journal_entries, 
        total_tags=total_tags, 
        total_words_in_journal_entries=total_words_in_journal_entries,
        pagination={},
        user_journal_entries=paginated_entries,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='profile',
        decrypt=decrypt,
        private_key=private_key
    )


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

        # Update the user
        status_code, message = update_user(user_id=user.id, data=json_body)

        if status_code == 200:
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
            logger.error(f"An error occurred while editing user profile: {user.username}.\nERROR: {message}")
    else:
        flash("Wrong password!", 'error')

    return redirect(url_for('auth.profile'))



@auth_bp.route('/export_data', methods=['POST'])
@login_required
def export_data():
    try:
        # Get the private_key and user_id
        json_data = {
            "user_id": current_user.id,
            "private_key": session.get('current_user_private_key')
        }

        # Get the user data
        data = export_user_data(**json_data)

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

        # Check file size
        file_size = os.path.getsize(file_path)

        # If file size is less than 24 MB, send via email
        if file_size < 24 * 1024 * 1024:  # Convert MB to bytes
            _email_html_text = render_template(
                'emails/export_data_email.html',
                username=current_user.fullname
            )

            msg = EmailMessage(
                sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                to=current_user.email,
                subject="Your MindCanvas data!",
                email_html_text=_email_html_text,
                attachments=[file_path]  # Use list for multiple attachments
            )

            try:
                msg.send(
                    sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                    server_info=EmailConfig.GMAIL_SERVER,
                    print_success_status=False
                )

                flash(f"An email containing '{file_name}' has been dispatched to your email address. Kindly save that file securely.", 'info')
                logger.info(f"EMAIL_SENT: Email with mindcanvas data has been emailed to '{current_user.fullname}'.")

                # Remove the user data after sending or downloading
                os.remove(file_path)

                # Redirect to the Profile page
                return redirect(url_for('auth.profile'))
    
            except Exception as e:
                # Handle email sending error
                flash('An error occurred while attempting to email MindCanvas data. Try again!', 'danger')
                logger.error(f"Error occurred while attempting to email MindCanvas data.\nERROR: {e}")


        else:
            # Send the file for download
            _res = send_file(
                file_path,
                as_attachment=True,
                mimetype='application/json',
                download_name=file_name
            )

            # Remove the user data after sending or downloading
            os.remove(file_path)

            return _res
        
        return redirect(url_for('auth.profile'))


    except Exception as e:
        # Error handling
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

                # Import the data!
                status_code, message = import_user_data(data=json_data)

                if status_code == 200:
                    return render_template('import_data.html', message='Data imported successfully.')
                elif status_code == 401:
                    flash(f"{message['message']}")
                elif status_code == 400:
                    flash(f"{message['message']}")
                else:
                    return render_template('import_data.html', message=f'Failed to import data. Please try again later.\n{message}')

            else:
                return render_template('import_data.html', message='Invalid file format. Please select a JSON file.')

        except Exception as e:
            return render_template('import_data.html', message=f'Error: {str(e)}')

    return render_template('import_data.html')