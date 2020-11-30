import os
from dotenv import load_dotenv
load_dotenv()

class Config(object):
    DEBUG = os.getenv("DEBUG")
    DB_USERNAME = os.getenv("DB_USERNAME")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    PORT= os.getenv('PORT')