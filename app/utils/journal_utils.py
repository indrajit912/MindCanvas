"""Utility functions for JournalEntry operations."""
# Author: Indrajit Ghosh
# Created On: Apr 18, 2024

from app.models.journal_entry import JournalEntry
from app.models.tag import Tag
from app.extensions import db
from scripts.utils import utcnow


def create_journal_entry(title:str, content:str, author_id:int, tags:list=None, locked=False, favourite=False):
    """Create a new journal entry.

    Args:
        title (str): The title of the journal entry.
        content (str): The content of the journal entry.
        author_id (int): The ID of the author of the journal entry.
        tags (list[str], optional): List of tag names associated with the journal entry.
        locked (bool, optional): Indicates whether the journal entry is locked.
        favourite (bool, optional): Indicates whether the journal entry is a favorite.

    Returns:
        tuple: A tuple containing a status code and a dictionary representation of the created journal entry.

    """
    try:
        # Create a new Journal Entry
        new_journal_entry = JournalEntry(
            title=title,
            content=content,
            author_id=author_id,
            locked=locked,
            favourite=favourite
        )

        # Add tags to the journal entry
        if tags:
            for tag_name in tags:
                # Getting the tags of the user with creator_id == author_id and name == tag_name
                tag = Tag.query.filter_by(name=tag_name, creator_id=author_id).first()
                if not tag:
                    # If tag does not exist, create a new tag
                    tag = Tag(
                        name=tag_name, 
                        creator_id=author_id,
                        color_red=128,
                        color_green=128,
                        color_blue=128
                    )
                    db.session.add(tag)
                new_journal_entry.tags.append(tag)

        # Add the new_journal_entry to the session
        db.session.add(new_journal_entry)

        # Commit the changes to the database
        db.session.commit()

        return 201, new_journal_entry.json()  # 201 indicates successful creation
    
    except Exception as e:
        db.session.rollback()
        error_message = f"An error occurred while creating the journal entry: {e}"
        return 500, {'error': error_message}
    


def update_existing_journal_entry(journal_entry_id, title=None, content=None, locked=None, favourite=None, tags=None):
    """Update a journal entry.

    Args:
        journal_entry_id (int): The ID of the journal entry to update.
        title (str, optional): The new title of the journal entry.
        content (str, optional): The new content of the journal entry.
        locked (bool, optional): Indicates whether the journal entry should be locked.
        favourite (bool, optional): Indicates whether the journal entry should be marked as a favorite.
        tags (list[str], optional): List of tag names to associate with the journal entry.

    Returns:
        tuple: A tuple containing a status code and a dictionary representation of the updated journal entry.

    """
    try:
        # Retrieve the journal entry to update
        journal_entry = JournalEntry.query.get_or_404(journal_entry_id)

        # Update attributes if provided
        if title is not None:
            journal_entry.title = title
        if content is not None:
            journal_entry.content = content
        if locked is not None:
            journal_entry.locked = locked
        if favourite is not None:
            journal_entry.favourite = favourite

        # Add tags to the journal entry
        _tags_to_add = []
        if tags:
            for tag_name in tags:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    # If tag does not exist, create a new tag
                    tag = Tag(
                        name=tag_name,
                        creator_id=journal_entry.author_id,
                        color_red=128,
                        color_green=128,
                        color_blue=128
                    )
                    db.session.add(tag)
                _tags_to_add.append(tag)

            journal_entry.tags = _tags_to_add

        journal_entry.last_updated = utcnow()

        db.session.commit()

        return 200, journal_entry.json()
    except Exception as e:
        db.session.rollback()
        error_message = f"An error occurred while updating the journal entry: {e}"
        return 500, {'error': error_message}

def delete_journal_entry(journal_entry_id:int):
    """Delete a journal entry.

    Args:
        journal_entry_id (int): The ID of the journal entry to delete.

    Returns:
        tuple: A tuple containing a status code and a dictionary with a message indicating the success of the operation.

    """
    try:
        # Retrieve the journal entry from the database using journal_entry_id
        journal_entry = JournalEntry.query.get_or_404(journal_entry_id)
        
        # Delete the journal entry
        db.session.delete(journal_entry)
        
        # Commit the changes to the database
        db.session.commit()
        
        return 200, {"message": "Journal entry deleted successfully"}
    except Exception as e:
        db.session.rollback()
        error_message = f"An error occurred while deleting the journal entry: {e}"
        return 500, {'error': error_message}