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

# Flask-Login
# https://flask-login.readthedocs.io/en/latest/
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    """
        is_authenticated
        This property should return True if the user is authenticated, i.e. they have provided
        valid credentials. (Only authenticated users will fulfill the criteria of login_required.)
    is_active
        This property should return True if this is an active user - in addition to being
        authenticated, they also have activated their account, not been suspended, or any
        condition your application has for rejecting an account. Inactive accounts may not log
        in (without being forced of course).
    is_anonymous
        This property should return True if this is an anonymous user. (Actual users should
        return False instead.)
    get_id()
        This method must return a unicode that uniquely identifies this user, and can be used to
        load the user from the user_loader callback. Note that this must be a unicode - if the
        ID is natively an int or some other type, you will need to convert it to unicode.

    To make implementing the user class easier, we inherit from UserMixin, which provides
    default implementations for all of these properties and methods.
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Create the database file and tables
if not os.path.isfile(DB_URL):
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    """
    This callback is used to reload the user object from the user ID stored in the session.
    It should take the unicode ID of a user, and return the corresponding user object.

    It should return None (not raise an exception) if the ID is not valid.
    (In that case, the ID will manually be removed from the session and processing will continue.)

    :param user_id: unicode user ID
    :return: user object
    """
    return User.get(user_id)


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
        password = request.form['password']

        # Angela's method:
        # PyCharm complains: Unexpected argument
        # Apparently it's because of the inclusion of the superclass 'UserMixin' in the class definition
        # new_user = User(
        #     email=request.form.get('email'),
        #     name=request.form.get('name'),
        #     password=request.form.get('password'),
        # )

        # Salting and Hashing Passwords
        # https://werkzeug.palletsprojects.com/en/1.0.x/utils/#module-werkzeug.security
        # Supported Hashing Algorithms
        # https://docs.python.org/3/library/hashlib.html
        #     Always available   Most platforms
        #   * md5                sha3_224
        #   * sha1               sha3_256
        #     sha224             sha3_384
        #     sha256             sha3_512
        #     sha384             shake_128
        #     sha512             shake_256
        #     blake2b
        #     blake2s
        #   * DO NOT USE - vulnerable to attack
        user.password = generate_password_hash(password, method='pbkdf2:sha3_512:100000', salt_length=8)

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
# # URL is "http://127.0.0.1:5008/secrets?username=John8"
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
