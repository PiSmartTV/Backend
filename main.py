from flask import Flask, url_for, redirect, render_template
from flask_dance.contrib.github import make_github_blueprint, github
import os

app = Flask(__name__)

github_client_secret = os.environ.get("GITHUB_CLIENT_SECRET")
github_client_id = os.environ.get("GITHUB_CLIENT_ID")

# google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
# google_client_id = os.environ.get("GOOGLE_CLIENT_ID")

app.config["SECRET_KEY"] = github_client_secret
# app.conifg["GOOGLE_OAUTH_CLIENT_ID"] = google_client_id
# app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = google_client_secret

github_blueprint = make_github_blueprint(
    client_id=github_client_id,
    client_secret=github_client_secret
)

app.register_blueprint(github_blueprint, url_prefix='/login/github')
@app.route("/")
def home():
    return render_template("index.html")


@app.route('/login/')
@app.route("/login")
def login():
    return render_template("login.html")


@app.route('/login/github/')
@app.route('/login/github')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))
    else:
        account_info = github.get('/user')
        if account_info.ok:
            account_info_json = account_info.json()
            return account_info_json

    return '<h1>Request failed!</h1>'


if __name__ == "__main__":
    app.run(debug=True, port=33507)
