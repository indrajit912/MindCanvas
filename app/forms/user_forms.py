# app/forms/user_forms.py
# Author: Indrajit Ghosh
# Created On: Mar 30, 2024
#

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired

class AddEntryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    tags = TextAreaField('Tags (separate with commas or spaces)')
    locked = BooleanField('Locked')
    submit = SubmitField('Add Entry')


class EditEntryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    tags = TextAreaField('Tags (separate with commas or spaces)')
    locked = BooleanField('Locked')
    submit = SubmitField('Update')