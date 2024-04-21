"""Utility functions for JournalEntry operations."""
# Author: Indrajit Ghosh
# Created On: Apr 18, 2024

from app.models.tag import Tag
from app.extensions import db
from scripts.utils import utcnow, sha256_hash
from app.utils.encryption import encrypt

def create_user_tag(name:str, creator_id:int, private_key, color_red:int=None, color_green:int=None, color_blue:int=None, description:str=None):
    """Create a new tag.

    Args:
        name (str): The name of the tag.
        creator_id (int): The ID of the creator of the tag.
        color_red (int, optional): The red component of the tag's color.
        color_green (int, optional): The green component of the tag's color.
        color_blue (int, optional): The blue component of the tag's color.
        description (str, optional): The description of the tag.

    Returns:
        tuple: A tuple containing a status code and a dictionary representation of the created tag.

    """
    try:
        # Preprocess the tag name for comparison
        processed_name = Tag.preprocess_tag_name(name)
    
        # Check if a tag with the same name already exists for the given creator_id
        existing_tag_same_creator = Tag.query.filter(
            (Tag.name_hash == sha256_hash(processed_name)) &
            (Tag.creator_id == creator_id)
        ).first()
        if existing_tag_same_creator:
            return 400, {'message': 'Tag with the same name already exists for this creator'}

        # Create a new Tag
        new_tag = Tag(
            name=encrypt(processed_name, private_key),
            creator_id=creator_id,
            color_red=color_red,
            color_green=color_green,
            color_blue=color_blue,
            description=description
        )
        # Set the name_hash
        new_tag.set_name_hash(tag_name=processed_name)

        # Add the new_tag to the database
        db.session.add(new_tag)
        db.session.commit()

        return 201, new_tag.json()  # 201 indicates successful creation
    except Exception as e:
        db.session.rollback()
        error_message = f"An error occurred while creating the tag: {e}"
        return 500, {'error': error_message}
    

def update_existing_tag(tag_id, private_key, name=None, color_red=None, color_green=None, color_blue=None, description=None):
    """Update a tag.

    Args:
        tag_id (int): The ID of the tag to update.
        name (str, optional): The new name of the tag.
        color_red (int, optional): The new red component of the tag's color.
        color_green (int, optional): The new green component of the tag's color.
        color_blue (int, optional): The new blue component of the tag's color.
        description (str, optional): The new description of the tag.

    Returns:
        tuple: A tuple containing a status code and a dictionary representation of the updated tag.

    """
    try:
        # Find the tag by ID
        tag = Tag.query.get_or_404(tag_id)

        # Update the tag attributes if provided
        if name is not None:
            # Preprocess the tag name for comparison
            processed_name = Tag.preprocess_tag_name(name)

            # Check if a tag with the same name already exists
            existing_tag = Tag.query.filter_by(name_hash=sha256_hash(processed_name)).first()
            if existing_tag:
                return 400, {'message': 'Tag with the same name already exists'}
            tag.name = encrypt(processed_name, private_key)
            tag.set_name_hash(processed_name)

        if color_red is not None:
            tag.color_red = color_red
    
        if color_green is not None:
            tag.color_green = color_green

        if color_blue is not None:
            tag.color_blue = color_blue

        if description is not None:
            tag.description = description

        tag.last_updated = utcnow()

        # Commit the changes to the database
        db.session.commit()

        return 200, tag.json()
    except Exception as e:
        db.session.rollback()
        error_message = f"An error occurred while updating the tag: {e}"
        return 500, {'error': error_message}
    

def delete_existing_tag(tag_id):
    """Delete a tag.

    Args:
        tag_id (int): The ID of the tag to delete.

    Returns:
        tuple: A tuple containing a status code and a dictionary with a message indicating the success of the operation.

    """
    try:
        # Retrieve the tag from the database using tag_id
        tag = Tag.query.get_or_404(tag_id)
        
        # Delete the tag
        db.session.delete(tag)
        
        # Commit the changes to the database
        db.session.commit()
        
        return 200, {"message": "Tag deleted successfully"}
    except Exception as e:
        db.session.rollback()
        error_message = f"An error occurred while deleting the tag: {e}"
        return 500, {'error': error_message}