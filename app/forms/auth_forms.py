# app/forms/auth_forms.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, IntegerField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Optional, Length, Email, ValidationError


class UserLoginForm(FlaskForm):
    email = EmailField("Email address", validators=[DataRequired()])
    passwd = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")



class EmailRegistrationForm(FlaskForm):
    fullname = StringField("Fullname", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])

    submit = SubmitField("Next")


class UserRegistrationForm(FlaskForm):
    passwd = PasswordField(
        "Password", 
        validators=[DataRequired(), EqualTo('confirm_passwd', message='Passwords must match')]
    )
    confirm_passwd = PasswordField("Confirm password")
    nickname = StringField("Nickname", validators=[Optional()])
    telegram = IntegerField("Telegram User ID", validators=[Optional()])

    submit = SubmitField("Register")


class ForgotPasswordForm(FlaskForm):
    email = EmailField(
        'Email',
        validators=[
            DataRequired(message='Email is required.')
        ]
    )
    submit = SubmitField('Submit')