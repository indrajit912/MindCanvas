# app/forms/user_forms.py
# Author: Indrajit Ghosh
# Created On: Mar 30, 2024
#

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange

class AddEntryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    tags = TextAreaField('Tags (separate with commas or spaces)')
    locked = BooleanField('Locked')
    submit = SubmitField('Add Entry')

class CreateNewTagForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('Description')
    color_red = IntegerField('Red', validators=[NumberRange(min=0, max=255)])
    color_green = IntegerField('Green', validators=[NumberRange(min=0, max=255)])
    color_blue = IntegerField('Blue', validators=[NumberRange(min=0, max=255)])
    submit = SubmitField('Create Tag')