# app/api/__init__.py

from flask import Blueprint

api_bp = Blueprint('api', __name__, url_prefix='/api')

from app.api import endpoints