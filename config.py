"""
config.py

Author: Indrajit Ghosh
Created on: Mar 24, 2024
"""
import os
from os.path import join, dirname
from dotenv import load_dotenv
from pathlib import Path
from secrets import token_hex

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

class Config:
    BASE_DIR = Path(__name__).parent.absolute()
    UPLOAD_DIR = BASE_DIR / 'uploads'
    LOG_FILE = BASE_DIR / 'app.log'
    PORT = os.environ.get("PORT") or 8080
    DATABASE_URI = os.environ.get("DATABASE_URI")

    FLASK_ENV = os.environ.get("FLASK_ENV") or 'production'
    if FLASK_ENV in ['dev', 'developement']:
        FLASK_ENV = 'development'
    elif FLASK_ENV in ['prod', 'production', 'pro']:
        FLASK_ENV = 'production'
    else:
        FLASK_ENV = 'development'
    
    SECRET_KEY = os.environ.get('SECRET_KEY') or token_hex(16)

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(Config.BASE_DIR, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = Config.DATABASE_URI or 'sqlite:///' + os.path.join(Config.BASE_DIR, 'app.db')
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

