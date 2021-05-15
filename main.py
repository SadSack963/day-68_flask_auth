from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os

API_KEY = 'any-secret-key-you-choose'
DB_URL = 'sqlite:///database/users.db'

app = Flask(__name__)

app.config['SECRET_KEY'] = API_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Create the database file and tables
if not os.path.isfile(DB_URL):
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Create a user and get the values from the HTML form
        user = User()
        user.name = request.form['name']
        user.email = request.form['email']
        user.password = request.form['password']

        # Angela's method:
        # PyCharm complains: Unexpected argument
        # Apparently it's because of the inclusion of the superclass 'UserMixin' in the class definition
        # new_user = User(
        #     email=request.form.get('email'),
        #     name=request.form.get('name'),
        #     password=request.form.get('password'),
        # )

        # Save the user in the database
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('secrets', username=user.name))
    return render_template("register.html")


@app.route('/login')
def login():
    return render_template("login.html")


# URL is "http://127.0.0.1:5008/secrets/John8"
@app.route('/secrets/<username>')
def secrets(username):
    return render_template("secrets.html", username=username)


# # Alternative by Manoj
# # URL is "http://127.0.0.1:5008/secrets?username=John7"
# @app.route('/secrets')
# def secrets():
#     username = request.args.get('username')
#     return render_template("secrets.html", username=username)


@app.route('/logout')
def logout():
    pass


@app.route('/download/<path:filename>')
def download(filename):
    # This is a secure way to serve files from a folder, such as static files or uploads.
    # Uses safe_join() to ensure the path coming from the client is not maliciously crafted
    # to point outside the specified directory
    return send_from_directory(
        directory='static/files', filename=filename, as_attachment=True
    )


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5008, debug=True)
