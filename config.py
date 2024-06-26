"""
config.py

Module for configuring the MindCanvas application.

Author: Indrajit Ghosh
Created on: Mar 24, 2024

This module provides configuration settings for the MindCanvas application,
including email configuration, environment settings, and database URIs.
"""

import os
from os.path import join, dirname
from dotenv import load_dotenv
from pathlib import Path
from secrets import token_hex

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

class EmailConfig:
    INDRAJITS_BOT_EMAIL_ID = os.environ.get("INDRAJITS_BOT_EMAIL_ID")
    INDRAJITS_BOT_EMAIL_PASSWD = os.environ.get("INDRAJITS_BOT_APP_PASSWORD")
    INDRAJIT912_GMAIL = os.environ.get("INDRAJIT912_GMAIL")
    GMAIL_SERVER = ['smtp.gmail.com', 587]

class Config:
    FLASK_APP = 'app'
    FLASK_APP_NAME = 'MindCanvas'

    BASE_DIR = Path(__name__).parent.absolute()
    APP_DATA_DIR = BASE_DIR / "app_data"
    LOG_FILE = BASE_DIR / f'{FLASK_APP_NAME.lower()}.log'
    
    DATABASE_URI = os.environ.get("DATABASE_URI")

    FLASK_ENV = os.environ.get("FLASK_ENV") or 'production'
    if FLASK_ENV in ['dev', 'developement']:
        FLASK_ENV = 'development'
    elif FLASK_ENV in ['prod', 'production', 'pro']:
        FLASK_ENV = 'production'
    else:
        FLASK_ENV = 'development'
    
    SECRET_KEY = os.environ.get('SECRET_KEY') or token_hex(16)
    SECRET_API_TOKEN = os.environ.get('SECRET_API_TOKEN') or token_hex(16)
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or token_hex(16)

class DevelopmentConfig(Config):
    PORT = os.environ.get("PORT") or 8080
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(Config.BASE_DIR, f'{Config.FLASK_APP_NAME.lower()}.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = Config.DATABASE_URI or \
        'sqlite:///' + os.path.join(Config.BASE_DIR, f'{Config.FLASK_APP_NAME.lower()}.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

def get_config():
    """
    Get the appropriate configuration based on the specified environment.
    :return: Config object
    """
    if Config.FLASK_ENV == 'production':
        return ProductionConfig()
    else:
        return DevelopmentConfig()
    

LOG_FILE = Config.LOG_FILE

