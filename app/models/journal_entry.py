# Models for the app
# 
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
# 

from app.extensions import db
import uuid
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
    date_created = db.Column(db.DateTime, nullable=False, default=lambda: utcnow)
    last_updated = db.Column(db.DateTime, default=utcnow)

    # Define foreign key relationship with User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Define many-to-many relationship with Tag
    tags = db.relationship('Tag', secondary=journal_entry_tag_association, backref=db.backref('journal_entries', lazy='dynamic'))

    def __repr__(self):
        return f"JournalEntry(title={self.title}, date_created={self.date_created})"
    
    def json(self):
        """Return a dictionary representation of the journal entry."""
        return {
            'id': self.id,
            'uuid': self.uuid,
            'title': self.title,
            'content': self.content,
            'locked': self.locked,
            'date_created': self.format_datetime_to_str(self.date_created),
            'last_updated': self.format_datetime_to_str(self.last_updated),
            'user_id': self.user_id,
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