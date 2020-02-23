from flask import Flask, url_for, redirect, render_template, request, abort
from flask_dance.contrib.github import make_github_blueprint, github
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from datetime import datetime
import os

app = Flask(__name__)


# Blueprints
github_client_secret = os.environ.get("GITHUB_CLIENT_SECRET")
github_client_id = os.environ.get("GITHUB_CLIENT_ID")
# google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
# google_client_id = os.environ.get("GOOGLE_CLIENT_ID")

# App Config
app.config["SECRET_KEY"] = github_client_secret
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SECRET_KEY"] = os.environ.get("SQL_SECRET_KEY")
# app.conifg["GOOGLE_OAUTH_CLIENT_ID"] = google_client_id
# app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = google_client_secret


# Make github blueprint
github_blueprint = make_github_blueprint(
    client_id=github_client_id,
    client_secret=github_client_secret
)
app.register_blueprint(github_blueprint, url_prefix='/login/github')

db = SQLAlchemy(app)

login_manager = LoginManager(app)
bcrypt = Bcrypt(app)

# User database


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    name = db.Column(db.String(126))
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)
    github = db.Column(db.Boolean(), default=False)
    google = db.Column(db.Boolean(), default=False)


# load user by id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home route
@app.route("/")
def home():
    return render_template("index.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        pass_hashed = user.password
        user_id = user.id

        if bcrypt.check_password_hash(pass_hashed, password):
            login_user(user)
            return "<h1>Yay</h1>"
        else:
            abort(401)
    else:
        return render_template("login.html")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get user entered fields
        username = request.form["username"]
        password = request.form["password"]
        name = request.form["name"]
        email = request.form["email"]

        new_user = User(
            username=username,
            email=email,
            name=name,
            password=bcrypt.generate_password_hash(password)
        )  # Create user
        try:
            db.session.add(new_user)  # Add to database
            db.session.commit()  # Commit changes
        except IntegrityError:
            return "<h1>Already exists!</h1>"  # If Unique rule is broke
        return "<h1>Yay</h1>"  # Success
    else:
        return render_template("register.html")


# @app.route('/login/github')
# def github_login():
#     if not github.authorized:
#         return redirect(url_for('github.login'))
#     else:
#         account_info = github.get('/user')
#         if account_info.ok:
#             account_info_json = account_info.json()
#             try:
#                 new_user = User(
#                     username=account_info_json["login"],
#                     email=account_info_json["email"],
#                     name=account_info_json["name"],
#                     github=True,
#                 )
#                 db.session.add(new_user)
#                 db.session.commit()
#             except IntegrityError:
#                 return "User already exists!"
#             return "User created!"
#     return '<h1>Request failed!</h1>'
if __name__ == "__main__":
    app.run()
