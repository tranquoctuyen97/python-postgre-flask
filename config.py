import os
from dotenv import load_dotenv

load_dotenv()

jwt_public_key_file = open('jwt_public.key', mode='r')
jwt_private_key_file = open('jwt_private.key', mode='r')
jwt_public_key = jwt_public_key_file.read()
jwt_private_key = jwt_private_key_file.read()
jwt_private_key_file.close()
jwt_public_key_file.close()


class Config(object):
    DEBUG = os.getenv("DEBUG")
    SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    PORT = os.getenv('PORT')
    JWT_PUBLIC_KEY = jwt_private_key
    JWT_PRIVATE_KEY = jwt_private_key
    JWT_ALGORITHM = "RS256"
