# app/main/__init__.py
#
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import Blueprint

main_bp = Blueprint(
    'main', 
    __name__,
    template_folder="templates", 
    static_folder="static"
)

from app.main import routes

