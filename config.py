import os

class Config:
    SECRET_KEY = 'dev-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///scssp.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Database file path
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.path.join(BASE_DIR, 'scssp.db')