from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config
from sqlalchemy import or_, DateTime
import bcrypt
import jwt
from sqlalchemy.sql import func
from uuid import uuid4
from sqlalchemy.dialects.postgresql import UUID
import os
from functools import wraps
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = Config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

is_debug_mode = Config.DEBUG == 'True' if True else False


# decorator for verifying the JWT

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'authorization' in request.headers:
            string_token = request.headers['authorization']
            token = string_token.split('Bearer ')[1]
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            current_user = jwt.decode(token.strip(), Config.JWT_SECRET_KEY, algorithms=Config.JWT_ALGORITHM)
            # current_user = User.query \
            #     .filter_by(public_id=data['public_id']) \
            #     .first()
        except NameError:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        return f(current_user, *args, **kwargs)

    return decorated


class UserModel(db.Model):
    __tablename__ = "users"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = db.Column(db.String(50))
    avatar = db.Column(db.String(50))
    username = db.Column(db.String(50))
    password = db.Column(db.String(255))
    email = db.Column(db.String(50))
    created_at = db.Column(DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(DateTime(timezone=True), onupdate=func.now())

    def __init__(self, name, username, password, email):
        self.name = name
        self.email = email
        self.username = username
        self.password = password


@app.route('/users', methods=['POST'])
def create_user():
    if request.is_json:
        data = request.get_json()
        username = data['username'].lower()
        email = data["email"].lower()
        name = data["name"]
        password = data["password"].encode('utf8')

        user_exist = UserModel.query.filter(or_(UserModel.username == username, UserModel.email == email)).first()

        if user_exist is not None:
            return {"error": "User exists"}

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password, salt)
        new_user = UserModel(name=name, username=username, password=hashed_password.decode('utf8'), email=email)
        db.session.add(new_user)
        db.session.commit()

        return {
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "name": new_user.name,
                "created_at": str(new_user.created_at.utcnow())
            }
        }

    else:
        return {"error": "The request payload is not in JSON format"}


@app.route('/login', methods=['POST'])
def login_user():
    if request.is_json:
        data = request.get_json()
        username = data["username"].lower()
        password = data["password"].encode('utf8')

        user = UserModel.query.filter(or_(UserModel.username == username, UserModel.email == username)).first()
        if user is None:
            return {"error": "User not found"}

        hashed_password = user.password.encode('utf8')
        is_match_password = bcrypt.checkpw(password, hashed_password)

        if is_match_password is False:
            return {"error": "Password wrong"}

        del user.password

        token = jwt.encode({
            "id": str(user.id),
            "name": user.name,
            "email": user.email,
            "username": user.username,
        }, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)

        return {
            "token": token.decode("utf-8"),
            "user": {
                "id": str(user.id),
                "name": user.name,
                "username": user.username,
                "email": user.email
            },
            "message": "success"
        }
    else:
        return {"error": "The request payload is not in JSON format"}


@app.route('/users/upload/avatar', methods=['POST'])
@token_required
def upload_avatar(user):
    if request.files:
        if not os.path.exists(Config.UPLOAD_DIR):
            os.makedirs(Config.UPLOAD_DIR)

        image = request.files["image"]
        ext = image.mimetype.split('/')[1]
        file_name = user["id"] + "-" + str(int(datetime.datetime.now().strftime("%Y%m%d%H%M%S"))) + f".{ext}"
        upload_path = os.path.join(
            Config.UPLOAD_DIR,
            file_name
        )
        image.save(upload_path)

        user_of_check = UserModel.query.get(user["id"])
        old_avatar = user_of_check.avatar

        user_of_check.avatar = file_name
        db.session.commit()

        if old_avatar is not None:
            remove_file_path = os.path.join(
                Config.UPLOAD_DIR,
                old_avatar
            )
            if os.path.exists(remove_file_path):
                os.remove(remove_file_path)

        return {"message": "success"}


@app.route('/users', methods=['PUT'])
@token_required
def update_user(user):
    if request.is_json:
        data = request.get_json()
        user = UserModel.query.get(user["id"])

        if 'password' in data:
            salt = bcrypt.gensalt()
            password = data["password"].encode('utf8')
            user.password = bcrypt.bcrypt.hashpw(password, salt)
        if 'name' in data:
            user.name = data["name"]
        db.session.commit()

    return {"message": "success"}


if __name__ == '__main__':
    app.run(is_debug_mode, port=Config.PORT)
