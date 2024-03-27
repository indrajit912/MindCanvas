"""
app/main/routes.py

This module defines the routes and views for the Flask web application.

Author: Indrajit Ghosh
Created on: Mar 24, 2024
"""
from . import main_bp
from flask import render_template
from werkzeug.exceptions import NotFound, InternalServerError, BadRequest, Unauthorized, Forbidden, \
    TooManyRequests

import logging


logger = logging.getLogger(__name__)


#######################################################
#                      Homepage
#######################################################
@main_bp.route('/')
def index():
    logger.info("Visited homepage.")
    return render_template("index.html")


@main_bp.route('/error/<error_code>')
def simulate_error(error_code):
    # Convert the error code to an integer
    error_code = int(error_code)

    # Raise an exception with the desired status code
    if error_code == 404:
        raise NotFound("Simulated 404 error")
    elif error_code == 500:
        raise InternalServerError("Simulated 500 error")
    elif error_code == 400:
        raise BadRequest("Simulated 400 error")
    elif error_code == 401:
        raise Unauthorized("Simulated 401 error")
    elif error_code == 403:
        raise Forbidden("Simulated 403 error")
    elif error_code == 429:
        raise TooManyRequests("Simulated 429 error")
    else:
        # You might want to handle other error codes accordingly
        raise Exception(f"Simulated error with code {error_code}")