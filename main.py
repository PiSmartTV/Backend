#!/usr/bin/env python3
import os
import string
import random
import datetime
from flask import Flask, url_for, redirect, render_template, request, jsonify
from flask_apscheduler import APScheduler
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_required, login_user,\
    logout_user, current_user
# from flask_dance.contrib.github import make_github_blueprint, github

app = Flask(__name__)

# Blueprints
# github_client_secret = os.environ.get("GITHUB_CLIENT_SECRET")
# github_client_id = os.environ.get("GITHUB_CLIENT_ID")
# google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
# google_client_id = os.environ.get("GOOGLE_CLIENT_ID")

# App Config
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SECRET_KEY"] = os.environ.get("SQL_SECRET_KEY")
app.config["SCHEDULER_API_ENABLED"] = True
# app.config["SECRET_KEY"] = github_client_secret
# app.conifg["GOOGLE_OAUTH_CLIENT_ID"] = google_client_id
# app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = google_client_secret


# Make github blueprint
# github_blueprint = make_github_blueprint(
#     client_id=github_client_id,
#     client_secret=github_client_secret
# )
# app.register_blueprint(github_blueprint, url_prefix='/login/github')

db = SQLAlchemy(app)

login_manager = LoginManager(app)

bcrypt = Bcrypt(app)

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()


def generate_token(leng=64):
    return ''.join([random.choice(string.ascii_lowercase+"0123456789")
                    for i in range(leng)])


def get_expire_date():
    return datetime.datetime.now() + datetime.timedelta(minutes=10)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    name = db.Column(db.String(128))
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    token = db.Column(db.String(64), nullable=False,
                      unique=True, default=generate_token)
    date_created = db.Column(db.DateTime, default=datetime.datetime.now)


class Code(db.Model):
    code = db.Column(db.String(8),
                     primary_key=True,
                     unique=True,
                     nullable=False)
    device_code = db.Column(db.String(128), unique=True, nullable=False)
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    expire_date = db.Column(db.DateTime, default=get_expire_date)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    return render_template("index.html")


@scheduler.task('interval', id='do_job_1', seconds=1, misfire_grace_time=900)
def delete_expired():
    expired = Code.query.filter(
        Code.expire_date <= datetime.datetime.now()
    ).all()

    if expired:
        print(f"Deleting {len(expired)} expired code(s)")

    for code in expired:
        db.session.delete(code)
        db.session.commit()


@app.route("/logout")
@login_required
def logout():
    logout_user(current_user)


@app.route("/code", methods=["GET", "POST"])
def code():
    if request.method == "GET":
        code = generate_token(8)
        device_code = generate_token(128)
        ip = request.remote_addr

        old_code = Code.query.filter_by(ip_address=ip).first()
        if old_code:
            old_code.code = code
            old_code.device_code = device_code
        else:
            new_code = Code(
                code=code,
                device_code=device_code,
                ip_address=ip,
                expire_date=get_expire_date()
            )
            db.session.add(new_code)

        db.session.commit()

        return jsonify({
            "message": "success",
            "response": "200",
            "code": code,
            "device_code": device_code
        }), 200


@app.route("/token", methods=["GET"])
@login_required
def token():
    return current_user.token


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user:
            pass_hashed = user.password

            if bcrypt.check_password_hash(pass_hashed, password):
                login_user(user)
                return jsonify({"message": "success", "response": "200"}), 200
            else:
                return jsonify({"message": "password is wrong", "response": "401"}), 401
        else:
            jsonify({"message": "username doesn't exist", "response": "401"}), 401
    else:
        return render_template("login.html")


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
            # If Unique rule is broke
            return jsonify({"message": "Already exists", "response": "401"}), 401
        # Success
        return jsonify({"message": "success", "response": "200"}), 200
    else:
        return render_template("register.html")


if __name__ == "__main__":
    app.run(port=80)
