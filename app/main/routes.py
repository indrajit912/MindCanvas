"""
app/main/routes.py

This module defines the routes and views for the Flask web application.

Author: Indrajit Ghosh
Created on: Mar 24, 2024
"""
from . import main_bp
from flask import render_template

import logging


logger = logging.getLogger(__name__)


#######################################################
#                      Homepage
#######################################################
@main_bp.route('/')
def index():
    logger.info("Visited homepage.")
    return render_template("index.html")

