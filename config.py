import os

class Config:
    SECRET_KEY = 'your-secret-key-here'
    UPLOAD_FOLDER = 'resources'
    PROTECTED_PATHS_FILE = 'protected_paths.txt'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ITEMS_PER_PAGE = 20