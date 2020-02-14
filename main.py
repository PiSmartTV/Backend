from flask import Flask, url_for, redirect, render_template
from flask_dance.contrib.github import make_github_blueprint, github

app = Flask(__name__)

with open("secret_key.txt", "r") as file:
    raw_txt = file.readlines()
    client_id = raw_txt[0][:-1]
    client_secret = raw_txt[1]

app.config["SECRET_KEY"] = client_secret

github_blueprint = make_github_blueprint(
    client_id=client_id,
    client_secret=client_secret
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
    app.run(debug=True)
