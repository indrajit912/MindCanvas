# app/utils/decorators.py
# Author: Indrajit Ghosh
# Created On: Mar 25, 2024

from functools import wraps

from flask import flash, redirect, url_for, request, jsonify, make_response
from flask_login import current_user

from config import EmailConfig, Config

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token or token != f"Bearer {Config.SECRET_API_TOKEN}":
            response = make_response(jsonify({'message': 'Unauthorized! Bearer token required.'}))
            response.status_code = 401
            return response

        return f(*args, **kwargs)
    return decorated_function


def logout_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash("You are already registered.", "info")
            return redirect(url_for("auth.dashboard"))
        return func(*args, **kwargs)

    return decorated_function

def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
            flash("Access restricted. Your account lacks the necessary permissions.", "info")
            return redirect(url_for("auth.dashboard"))
        return func(*args, **kwargs)

    return decorated_function

def indrajit_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.email != EmailConfig.INDRAJIT912_GMAIL:
            flash("Access restricted. Your account lacks the necessary permissions.", "info")
            return redirect(url_for("auth.dashboard"))
        return func(*args, **kwargs)

    return decorated_function