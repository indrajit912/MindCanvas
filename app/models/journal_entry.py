# app/models/journal_entry.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
# 

# Standard library imports
import uuid

# Local application imports
from app.extensions import db
from scripts.utils import utcnow


# Association Table for many-to-many relationship between JournalEntry and Tag
journal_entry_tag_association = db.Table(
    'journal_entry_tag',
    db.Column('journal_entry_id', db.Integer, db.ForeignKey('journal_entry.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)


class JournalEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: uuid.uuid4().hex)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    locked = db.Column(db.Boolean, default=False)
    favourite = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_updated = db.Column(db.DateTime(timezone=True), default=utcnow)

    # Define foreign key relationship with User
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Define many-to-many relationship with Tag
    tags = db.relationship('Tag', secondary=journal_entry_tag_association, backref=db.backref('journal_entries', lazy='dynamic'))

    def __repr__(self):
        return f"JournalEntry(title={self.title}, date_created={self.date_created})"
    
    def json(self):
        """Return a dictionary representation of the journal entry."""
        return {
            'id': self.id,
            'uuid': self.uuid,
            'title': self.title.decode() if isinstance(self.title, bytes) else self.title,
            'content': self.content.decode() if isinstance(self.content, bytes) else self.content,
            'locked': self.locked,
            'favourite': self.favourite,
            'date_created': self.format_datetime_to_str(self.date_created),
            'last_updated': self.format_datetime_to_str(self.last_updated),
            'author_id': self.author_id,
            'tags': [tag.json() for tag in self.tags]
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
