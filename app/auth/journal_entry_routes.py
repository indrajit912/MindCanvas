# Standard library imports
import logging
from math import ceil
from datetime import datetime, timedelta

# Third-party imports
from flask import abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required
from sqlalchemy import desc, extract

# Local application imports
from app.forms.user_forms import AddEntryForm
from app.models.journal_entry import JournalEntry
from app.models.tag import Tag
from app.models.user import User
from app.utils.encryption import decrypt
from app.utils.journal_utils import create_journal_entry, delete_journal_entry, update_existing_journal_entry
from scripts.utils import convert_utc_to_ist_str

# Relative imports
from . import auth_bp
from .routes import redirect_to_destination

logger = logging.getLogger(__name__)
    
@auth_bp.route('/users/<int:user_id>/add_entry', methods=['GET', 'POST'])
@login_required
def add_entry(user_id):
    # Check if the current user is authorized to add an entry for the specified user
    if current_user.id != user_id:
        abort(403)  # Forbidden

    form = AddEntryForm()

    # Get the current_user's private key from session
    user_private_key = session['current_user_private_key']

    # Tags those are already created by the current_user
    user_tags = current_user.tags

    if form.validate_on_submit():

        # Split the input string to get a list of tags
        tags_for_the_new_entry = [Tag.preprocess_tag_name(tag.strip()) for tag in form.tags.data.split(',') if tag.strip()]

        # Create a json body for the new entry
        entry_json = {
            "title": form.title.data,
            "content": form.content.data,
            "author_id": current_user.id,
            "tags": tags_for_the_new_entry,
            "locked": form.locked.data
        }

        # Create the entry!
        status_code, message = create_journal_entry(**entry_json, private_key=user_private_key)

        # Check the response status code and flash messages accordingly
        if status_code == 201:
            flash('Journal entry added successfully!', 'success')
            logger.info(f"A new JournalEntry added by `{current_user.username}`.")
            # If the user is authorized, redirect to the route
            return redirect(url_for('auth.user_journal_entries', user_id=current_user.id))
        else:
            flash('Failed to add journal entry. Please try again later.', 'error')
            logger.error(f"`{current_user.username}` tried to add a new JournalEntry but error occurred.\nError Message: {message}")


        # Remove the user data
        form = AddEntryForm(formdata=None)

    # Render the add entry form template
    return render_template('add_entry.html', form=form, user_tags=user_tags, decrypt=decrypt, private_key=user_private_key)


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

    # Get the page number from the request or default to the first page
    page = request.args.get('page', 1, type=int)
    per_page = 30

    # Count the total number of journal entries, tags, and words
    total_journal_entries = user_portfolio['total_journal_entries']
    total_tags = user_portfolio['total_tags']
    total_words_in_journal_entries = user_portfolio['total_words']

    # Query all JournalEntry objects associated with the specified user_id
    user_journal_entries = JournalEntry.query.filter_by(
        author_id=user_id
    ).order_by(JournalEntry.date_created.desc()).all()

    # Paginate the entries manually
    total_entries = len(user_journal_entries)
    total_pages = ceil(total_entries / per_page)
    start_index = (page - 1) * per_page
    end_index = min(start_index + per_page, total_entries)
    paginated_entries = user_journal_entries[start_index:end_index]

    return render_template(
        'user_all_entries.html',
        pagination={
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            'iter_pages': range(1, total_pages + 1),
            'page': page
        },
        user_journal_entries=paginated_entries,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='user-all-entries',
        total_journal_entries=total_journal_entries,
        total_tags=total_tags,
        total_words_in_journal_entries=total_words_in_journal_entries,
        decrypt=decrypt,
        private_key=private_key,
        route_url='auth.user_journal_entries'
    )


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
    entry_content:str = request.form.get('content')
    entry_tags:list =  [Tag.preprocess_tag_name(tag.strip()) for tag in request.form['tags'].split(',') if tag.strip()]
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

    # Make the journal_entry json
    entry_data = {
        "journal_entry_id": journal_entry.id,
        "title": entry_title,
        "content": entry_content,
        "tags": entry_tags,
        "locked": entry_locked
    }

    # Update the JournalEntry!
    status_code, message = update_existing_journal_entry(**entry_data, private_key=user_private_key)

    # Check the response status code and flash messages accordingly
    if status_code == 200:
        logger.info(f"JournalEntry updated by `{current_user.username}`.")
        flash('Journal entry updated successfully!', 'success')
        
    else:
        logger.error(f"`{current_user.username}` tried to update journal entry but error occurred\n{message}.")
        flash('Failed to update journal entry. Please try again later.', 'error')
        
    
    # If the user is authorized, redirect to the route
    return redirect(url_for('auth.view_entry', entry_id=journal_entry_id))


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
        # Delete the entry!
        status_code, message = delete_journal_entry(journal_entry_id)
        if status_code == 200:
            logger.info(f"JournalEntry deleted successfully by {current_user.username}!")
            flash(f"JournalEntry deleted successfully!", "success")
        else:
            logger.error(f"An error occurred while deleting the JournalEntry with ID {journal_entry_id}.\nERROR: {message}")
            flash("An error occurred during JournalEntry deletion. Please try again.", 'error')
    
    return redirect_to_destination(destination)


@auth_bp.route('/favourites/<int:user_id>', methods=['GET'])
@login_required
def favourites(user_id):
    if user_id != current_user.id:
        abort(404)

    # Get the current user's private key from session
    private_key = session['current_user_private_key']

    # Get the page number from the request or default to the first page
    page = request.args.get('page', 1, type=int)
    per_page = 30

    favourite_journal_entries = JournalEntry.query.filter(
        (JournalEntry.author_id == current_user.id) &
        (JournalEntry.favourite == True)
    ).order_by(JournalEntry.date_created.desc()).all()

    # Paginate the entries manually
    total_entries = len(favourite_journal_entries)
    total_pages = ceil(total_entries / per_page)
    start_index = (page - 1) * per_page
    end_index = min(start_index + per_page, total_entries)
    paginated_entries = favourite_journal_entries[start_index:end_index]


    return render_template(
        'favourites.html', 
        pagination={
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            'iter_pages': range(1, total_pages + 1),
            'page': page
        },
        user_journal_entries=paginated_entries,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='favourites',
        private_key=private_key,
        decrypt=decrypt
    )


@auth_bp.route('/toggle_entry_lock', methods=['POST'])
@login_required
def toggle_entry_lock():

    # Get the password and `journal_entry_id` from the form
    password = request.form.get('password')
    journal_entry_id  = request.form.get('journal_entry_id')
    destination = request.form.get('destination')

    # Get the current_user's private key from session
    user_private_key = session['current_user_private_key']

    # Get the JournalEntry by ID
    journal_entry = JournalEntry.query.get_or_404(journal_entry_id)

    # Make sure that the current_user is the author of this journal entry
    if not journal_entry.author_id == current_user.id:
        abort(403)

    # Check if the password is correct
    if current_user.check_password(password):
        # Toggle the locked attribute of the journal_entry
        payload = {
            "journal_entry_id": journal_entry.id,
            "locked": not journal_entry.locked
        }

        # Update the JournalEntry!
        status_code, message = update_existing_journal_entry(**payload, private_key=user_private_key)
        
        if status_code == 200:
            logger.info(f"`{current_user.username}` changed the `locked` status of one of their JournalEntry.")
            flash("The 'locked' status of the JournalEntry has been updated!", 'success')
        else:
            logger.error(f"Failed to update journal entry locked status.\n{message}")
            flash(f"ERROR: Failed to update journal entry locked status. Status code: {status_code}", 'error')
    else:
        flash('Incorrect password. Please try again.', 'error')

    return redirect_to_destination(destination)


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


# Route to toggle the is_admin value
@auth_bp.route('/toggle_entry_favourite', methods=['POST'])
@login_required
def toggle_entry_favourite():
    # Get the password and `journal_entry_id` from the form
    journal_entry_id  = request.form.get('journal_entry_id')
    destination = request.form.get('destination')

    # Get the JournalEntry by ID
    journal_entry = JournalEntry.query.get_or_404(journal_entry_id)

    # Get the current_user's private key from session
    user_private_key = session['current_user_private_key']

    # Make sure that the current_user is the author of this journal entry
    if not journal_entry.author_id == current_user.id:
        abort(403)

    # Toggle the favourite attribute of the journal_entry
    payload = {
        "journal_entry_id": journal_entry.id,
        "favourite": not journal_entry.favourite
    }

    # Update the JournalEntry!
    status_code, message = update_existing_journal_entry(**payload, private_key=user_private_key)
        
    if status_code == 200:
        logger.info(f"`{current_user.username}` changed the `favourite` status of one of their JournalEntry.")
        flash("The 'favourite' status of the JournalEntry has been updated!", 'success')
    else:
        logger.error(f"Failed to update journal entry favourite status. Status code: {status_code}\n{message}")
        flash(f"API_ERROR: Failed to update journal entry favourite status. Status code: {status_code}", 'error')

    return redirect_to_destination(destination)


@auth_bp.route('/user/<int:user_id>/journal_entries/tag/<int:tag_id>', methods=['GET'])
@login_required
def get_journal_entries_by_tag(user_id, tag_id):
    # Find the user by user_id
    user = User.query.get_or_404(user_id)

    # Get the page number from the request or default to the first page
    page = request.args.get('page', 1, type=int)
    per_page = 30

    # Ensure the tag belongs to the user
    tag = Tag.query.filter_by(id=tag_id, creator_id=user_id).first()
    if not tag:
        abort(404)

    # Query journal entries associated with the tag for the user
    journal_entries = JournalEntry.query.join(JournalEntry.tags).filter_by(id=tag_id, creator_id=user_id).order_by(
        desc(JournalEntry.date_created)
    ).all()

    # Get user's private key
    private_key = session['current_user_private_key']

    # Paginate the entries manually
    total_entries = len(journal_entries)
    total_pages = ceil(total_entries / per_page)
    start_index = (page - 1) * per_page
    end_index = min(start_index + per_page, total_entries)
    paginated_entries = journal_entries[start_index:end_index]

    return render_template(
        'journal_entries_by_tag.html', 
        pagination={
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            'iter_pages': range(1, total_pages + 1),
            'page': page
        },
        user_journal_entries=paginated_entries,
        user=user, 
        tag=tag,
        decrypt=decrypt,
        private_key=private_key,
        convert_utc_to_ist_str=convert_utc_to_ist_str
    )


@auth_bp.route('/search/<int:user_id>', methods=['GET'])
@login_required
def search(user_id):
    # Check if the current user is authorized to access the search functionality
    if not current_user.id == user_id:
        abort(403)

    # Initialize variables
    query = "Search ..."
    private_key = session.get('current_user_private_key')

    # Get search query and date filters from URL parameters
    query = request.args.get('q', query)
    given_date_str = request.args.get('given_date', None)

    search_results = []

    # Parse date strings into datetime objects if provided
    given_date = datetime.strptime(given_date_str, "%Y-%m-%d") if given_date_str else None

    # Filter entries based on date and/or query
    if given_date:
        # Filter entries by date if given_date is provided
        user_entries = JournalEntry.query.filter(
            JournalEntry.author_id == user_id,
            extract('year', JournalEntry.date_created) == given_date.year,
            extract('month', JournalEntry.date_created) == given_date.month,
            extract('day', JournalEntry.date_created) == given_date.day
        ).order_by(desc(JournalEntry.date_created)).all()
    else:
        # Query all JournalEntry objects associated with the specified user_id
        user_entries = JournalEntry.query.filter_by(author_id=user_id).order_by(
            desc(JournalEntry.date_created)
        ).all()

    # If a query is provided, filter the entries based on the query
    if query:
        search_results = [
            entry for entry in user_entries
            if query.lower() in decrypt(entry.title, private_key).lower()
            or query.lower() in decrypt(entry.content, private_key).lower()
        ]
    else:
        search_results = user_entries

    # Paginate the search results
    page = request.args.get('page', 1, type=int)
    total_entries = len(search_results)
    per_page = 30
    total_pages = ceil(total_entries / per_page)
    start_index = (page - 1) * per_page
    end_index = min(start_index + per_page, total_entries)
    paginated_entries = search_results[start_index:end_index]

    return render_template(
        'search.html',
        user_id=current_user.id,
        pagination={
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            'iter_pages': range(1, total_pages + 1),
            'page': page
        },
        user_journal_entries=paginated_entries,
        query=query,
        decrypt=decrypt,
        private_key=private_key,
        convert_utc_to_ist_str=convert_utc_to_ist_str,
        redirect_destination='search',
        route_url='auth.search',
        total_entries=total_entries,
        given_date=given_date_str
    )

