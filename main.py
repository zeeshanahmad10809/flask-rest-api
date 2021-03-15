import datetime
import logging
import uuid
import jwt  # pip install PYJWT
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_uploads import (
    UploadSet,
    configure_uploads,
    IMAGES,
)  # pip install Flask-Uploads

app = Flask(__name__)
app.config["SECRET_KEY"] = "thisissecret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///Sample.db"
app.config["UPLOADED_PHOTOS_DEST"] = "uploads"
photos = UploadSet("photos", IMAGES)
configure_uploads(app, photos)

db = SQLAlchemy(app)
db.create_all()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    author = db.Column(db.String(20))
    publisher = db.Column(db.String(50))
    user_id = db.Column(db.Integer)  # refers to id of User...


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
            current_user = User.query.filter_by(public_id=data["public_id"]).first()
        except:
            return jsonify({"message": "Token is invalid!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/upload", methods=["POST"])
def upload():
    if "photo" in request.files:
        filename = photos.save(request.files["photo"])
        return jsonify({"file name": filename})

    return jsonify({"message": "Image not uploaded"})


@app.route("/login", methods=["GET"])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required!"'},
        )

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required!"'},
        )

    if check_password_hash(user.password, auth.password):
        # if auth.password == user.password:
        token = jwt.encode(
            {
                "public_id": user.public_id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
            },
            app.config["SECRET_KEY"],
        )
        return jsonify({"token": token.decode("UTF-8")})

    return make_response(
        "Could not verify", 401, {"WWW-Authenticate": 'Basic realm="Login required!"'}
    )


@app.route("/form_signup", methods=["POST"])
def form_signup():
    logging.log(logging.INFO, "Approached!")
    return jsonify(
        {
            "user_name": request.form.get("user_name"),
            "user_password": request.form.get("user_password"),
        }
    )


@app.route("/signup", methods=["POST"])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="sha256")
    new_user = User(
        public_id=str(uuid.uuid4()),
        name=data["name"],
        password=hashed_password,
        admin=False,
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Account created!"})


@app.route("/")
def home():
    return jsonify({"message": "This is home page!"})


@app.route("/book", methods=["GET"])
@token_required
def get_all_books(current_user):

    if not current_user.admin:
        books = Book.query.filter_by(user_id=current_user.id).all()
        output = []

        for book in books:
            book_data = {}
            book_data["id"] = book.id
            book_data["name"] = book.name
            book_data["author"] = book.author
            book_data["publisher"] = book.publisher
            output.append(book_data)
    else:
        books = Book.query.all()
        output = []
        for book in books:
            book_data = {}
            book_data["id"] = book.id
            book_data["name"] = book.name
            book_data["author"] = book.author
            book_data["publisher"] = book.publisher
            output.append(book_data)

    return jsonify(output)


@app.route("/book/<book_id>", methods=["GET"])
@token_required
def get_one_book(current_user, book_id):
    book = Book.query.filter_by(id=book_id, user_id=current_user.id).first()

    if not book:
        return jsonify({"message": "No book found!"})

    book_data = {}
    book_data["id"] = book.id
    book_data["name"] = book.name
    book_data["author"] = book.author
    book_data["publisher"] = book.publisher

    return jsonify(book_data)


@app.route("/book", methods=["POST"])
@token_required
def add_book(current_user):
    data = request.get_json()
    new_book = Book(
        name=data["name"],
        author=data["author"],
        publisher=data["publisher"],
        user_id=current_user.id,
    )
    db.session.add(new_book)
    db.session.commit()

    return jsonify({"message": "Book added!"})


@app.route("/book/<book_id>", methods=["PUT"])
@token_required
def update_book(current_user, book_id):
    data = request.get_json()
    book = Book.query.filter_by(id=book_id, user_id=current_user.id).first()

    if not book:
        return jsonify({"message": "No book found!"})

    book.name = data["name"]
    book.author = data["author"]
    book.publisher = data["publisher"]
    db.session.commit()

    return jsonify({"message": "Book item has been updated!"})


@app.route("/book/<book_id>", methods=["DELETE"])
@token_required
def delete_book(current_user, book_id):
    book = Book.query.filter_by(id=book_id, user_id=current_user.id).first()
    if not book:
        return jsonify({"message": "No book found!"})

    db.session.delete(book)
    db.session.commit()

    return jsonify({"message": "Book deleted!"})


if __name__ == "__main__":
    # app.run(host='0.0.0.0', debug=True)
    app.run()
    # Type in terminal to get ip....  ifconfig | grep "inet " | grep -v 127.0.0.1
