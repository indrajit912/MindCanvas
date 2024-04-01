# app/models/tag.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
# 

from app.extensions import db
import uuid
import random
from scripts.utils import utcnow


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: uuid.uuid4().hex)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    color_red = db.Column(db.Integer, default=lambda: random.randint(0, 255))
    color_green = db.Column(db.Integer, default=lambda: random.randint(0, 255))
    color_blue = db.Column(db.Integer, default=lambda: random.randint(0, 255))
    date_created = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_updated = db.Column(db.DateTime(timezone=True), default=utcnow)

    # Define the foreign key relationship with User
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, name, creator_id, color_red=None, color_green=None, color_blue=None, description=None):
        """
        Initializes a new Tag instance.
        """
        self.name = self.preprocess_tag_name(name)
        self.creator_id = creator_id
        self.color_red = color_red
        self.color_green = color_green
        self.color_blue = color_blue
        self.description = description

    def __repr__(self):
        return f"Tag(name={self.name})"
    
    @staticmethod
    def preprocess_tag_name(name):
        """
        Preprocesses the tag name by converting it to lowercase, stripping whitespace, and replacing spaces with dashes.

        Parameters:
            name (str): The original tag name.

        Returns:
            str: The processed tag name.
        """
        processed_name = name.lower().strip().replace(' ', '-')
        return processed_name

    def color_rgb(self):
        return f'rgb({self.color_red}, {self.color_green}, {self.color_blue})'
    
    @staticmethod
    def hex_to_rgb(hex_color):
        """
        Convert a hexadecimal color code to RGB values.
    
        Args:
            hex_color (str): The hexadecimal color code in the format '#RRGGBB'.
    
        Returns:
            tuple: A tuple containing the RGB values as integers (red, green, blue).
        """
        # Remove '#' if present
        if hex_color.startswith('#'):
            hex_color = hex_color[1:]
    
        # Convert hexadecimal to RGB
        red = int(hex_color[0:2], 16)
        green = int(hex_color[2:4], 16)
        blue = int(hex_color[4:6], 16)
    
        return red, green, blue
    
    def color_hex(self):
        """
        Returns the hexadecimal color code representation of the RGB color values.

        Returns:
            str: Hexadecimal color code representing the RGB values.
        """
        hex_color = '#{:02x}{:02x}{:02x}'.format(self.color_red, self.color_green, self.color_blue)
        return hex_color
    
    def json(self):
        """Return a dictionary representation of the tag."""
        return {
            'id': self.id,
            'uuid': self.uuid,
            'name': self.name,
            'description': self.description,
            'color_red': self.color_red,
            'color_green': self.color_green,
            'color_blue': self.color_blue,
            'color_hex': self.color_hex(), 
            'creator_id': self.creator_id,
            'date_created': self.format_datetime_to_str(self.date_created),
            'last_updated': self.format_datetime_to_str(self.last_updated)
        }
    
    @staticmethod
    def format_datetime_to_str(dt):
        """
        Formats a datetime object to the UTC string format: "Wed, 27 Mar 2024 07:10:10 UTC".

        Parameters:
            dt (datetime): A datetime object to be formatted.

        Returns:
            str: A string representing the datetime object in the UTC format.
        """
        return dt.strftime('%a, %d %b %Y %H:%M:%S UTC')
