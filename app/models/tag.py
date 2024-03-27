# app/models/tag.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
# 

from app.extensions import db
import uuid
from scripts.utils import utcnow


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: uuid.uuid4().hex)
    name = db.Column(db.String(50), nullable=False)
    color_red = db.Column(db.Integer, default=128)
    color_green = db.Column(db.Integer, default=128)
    color_blue = db.Column(db.Integer, default=128)
    date_created = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_updated = db.Column(db.DateTime, default=utcnow)

    # Define the foreign key relationship with User
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Tag(name={self.name})"

    def color_rgb(self):
        return f'rgb({self.color_red}, {self.color_green}, {self.color_blue})'
    
    def json(self):
        """Return a dictionary representation of the tag."""
        return {
            'id': self.id,
            'uuid': self.uuid,
            'name': self.name,
            'color_red': self.color_red,
            'color_green': self.color_green,
            'color_blue': self.color_blue,
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