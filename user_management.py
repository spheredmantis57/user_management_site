"""
starter code from: https://github.com/PrettyPrinted/youtube_video_code/tree/master/2017/03/03/Build%20a%20User%20Login%20System%20With%20Flask-Login%2C%20Flask-WTForms%2C%20Flask-Bootstrap%2C%20and%20Flask-SQLAlchemy/building_user_login_system/finish
"""
from dataclasses import dataclass
from random import choice as rand_choice
from string import ascii_letters, digits
from os.path import dirname, abspath, join, exists
from flask import Flask, render_template, redirect, url_for, flash, Blueprint, send_from_directory
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

def main():
    full_app = create_app()
    init_db(full_app)
    full_app.app.run()

########################## START: SET UP APP ###################################

@dataclass
class AppWithUserManagement:
    app: Flask
    database: SQLAlchemy
    db_path: str

class UserAlreadyExists(Exception):
    """Exception for a user already exists when trying to add a user"""

USER_MANAGEMENT_BP = Blueprint("user_management", __name__, template_folder="templates", static_folder="static")

DATABASE = SQLAlchemy()
LOGIN_MANGER = LoginManager()
@LOGIN_MANGER.unauthorized_handler
def unauthorized_callback():
    flash("You need to be logged in to access that page.", "warning")
    return redirect(url_for("user_management.login"))

USERNAME_MIN = 4
USERNAME_MAX = 20
PASSWORD_MIN = 8
PASSWORD_MAX = 30
EMAIL_MAX = 50
TOKEN_LEN = 32

def create_app(database_path=join(dirname(abspath(__file__)), ".login.db")):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "Wow...oh so secret!!!"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:////{database_path}"
    bootstrap = Bootstrap(app) # needed to use bootstrap templates
    DATABASE.init_app(app)
    LOGIN_MANGER.init_app(app)
    LOGIN_MANGER.login_view = "login"

    app.register_blueprint(USER_MANAGEMENT_BP, url_prefix="/UserManagement")

    full_app = AppWithUserManagement(app, DATABASE, database_path)

    return full_app

def init_db(full_app):
    """
    Initialized the database if it does not exist yet
    """
    if not exists(full_app.db_path):
        with full_app.app.app_context():
            DATABASE.create_all()

class User(UserMixin, DATABASE.Model):
    id = DATABASE.Column(DATABASE.Integer, primary_key=True)
    username = DATABASE.Column(DATABASE.String(USERNAME_MAX), unique=True, nullable=False)
    email = DATABASE.Column(DATABASE.String(EMAIL_MAX), unique=True, nullable=False)
    password = DATABASE.Column(DATABASE.String(PASSWORD_MAX), nullable=False)
    email_verified = DATABASE.Column(DATABASE.Boolean, default=False)
    validation_tokens = DATABASE.relationship("ValidationToken", back_populates="user")

class ValidationToken(UserMixin, DATABASE.Model):
    validation_token = DATABASE.Column(DATABASE.String(TOKEN_LEN), unique=True, nullable=False, primary_key=True)
    user_id = DATABASE.Column(DATABASE.Integer, DATABASE.ForeignKey('user.id'))
    user = DATABASE.relationship("User", back_populates="validation_tokens")

class LoginForm(FlaskForm):
    username = StringField("username", validators=[InputRequired(), Length(min=USERNAME_MIN, max=USERNAME_MAX)])
    password = PasswordField("password", validators=[InputRequired(), Length(min=PASSWORD_MIN, max=PASSWORD_MAX)])
    remember = BooleanField("remember me")

class RegisterForm(FlaskForm):
    email = StringField("email", validators=[InputRequired(), Email(message="Invalid email"), Length(max=EMAIL_MAX)])
    username = StringField("username", validators=[InputRequired(), Length(min=USERNAME_MIN, max=USERNAME_MAX)])
    password = PasswordField("password", validators=[InputRequired(), Length(min=PASSWORD_MIN, max=PASSWORD_MAX)])

@USER_MANAGEMENT_BP.route("/")
def index():
    return render_template("index.html")

@USER_MANAGEMENT_BP.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

########################## END: SET UP APP #####################################

########################## START: CURRENT USER OPERATIONS ######################

@LOGIN_MANGER.user_loader
def load_user(user_id):
    return DATABASE.session.get(User, user_id)

@USER_MANAGEMENT_BP.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if not form.validate_on_submit():
        return render_template("login.html", form=form)

    user = User.query.filter_by(username=form.username.data).first()
    if (user is None) or (check_password_hash(user.password, form.password.data) is False):
        return "<h1>Invalid username or password</h1>"
    if user.email_verified is False:
        # todo look at return
        return "<h1>Need to verify email before logging in. NEED TO HAVE AN OPTION TO RESEND</h1>"
    login_user(user, remember=form.remember.data)

    return redirect(url_for("user_management.dashboard"))

@USER_MANAGEMENT_BP.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.username)

@USER_MANAGEMENT_BP.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("user_management.index"))

########################## END: CURRENT USER OPERATIONS ########################

########################## START: SIGNING UP ###################################
def generate_token(length):
    """Generates a verification token for a verification email

    Returns:
        str: the generated token
    """
    characters = ascii_letters + digits
    token = ''.join(rand_choice(characters) for _ in range(length))
    return token

@USER_MANAGEMENT_BP.route("/verify/<token>")
def verify_email(token):
    validation_token = DATABASE.session.query(ValidationToken).filter_by(validation_token=token).first()
    if validation_token:
        user = validation_token.user
        user.email_verified = True
        DATABASE.session.delete(validation_token)
        DATABASE.session.commit()
        return "<h1>Email has been verified!</h1>"
    return "<h1>Invalid or expired token.</h1>"

# todo create an email that will send this email out
# todo watch https://www.youtube.com/watch?v=vF9n248M1yk to get the info how to send it
def send_verification_email(email, token):
    verification_link = url_for("user_management.verify_email", token=token, _external=True)
    subject = "Verify Your Email"
    message = f"Click the following link to verify your email: {verification_link}"
    print(f"Email sent to {email} with verification link: {verification_link}")

@USER_MANAGEMENT_BP.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()

    if not form.validate_on_submit():
        return render_template("signup.html", form=form)

    try:
        new_user = add_user(form.username.data, form.password.data, form.email.data)
    except UserAlreadyExists as ex:
        return f"<h1>Cannot create: {ex}</h1>"

    while True:
        # loop till we generate a token that has not been taken yet
        token = generate_token(TOKEN_LEN)
        existing_token = ValidationToken.query.filter_by(validation_token=token).first()
        if existing_token is None:
            break

    validation_token = ValidationToken(validation_token=token, user=new_user)

    try:
        DATABASE.session.add(validation_token)
        DATABASE.session.commit()
    except UserAlreadyExists as ex:
        return f"<h1>Account Creation Failed: {ex}</h1>"
    send_verification_email(form.email.data, token)

    return "<h1>New user has been created! Check your email to verify.</h1>"

def add_user(username, password, email, email_verified=False):
    # check that unique fields are going to be unique
    query_username = User.query.filter_by(username=username).first()
    query_email = User.query.filter_by(email=email).first()
    if query_username is not None:
        raise UserAlreadyExists("This username has already been taken")
    if query_email is not None:
        raise UserAlreadyExists("This email already has an account")

    hashed_password = generate_password_hash(password, method="scrypt")
    new_user = User(username=username, email=email, password=hashed_password, email_verified=email_verified)

    DATABASE.session.add(new_user)
    # DATABASE.session.add(default_category)
    DATABASE.session.commit()
    return new_user

########################## END: SIGNING UP ###################################


if __name__ == "__main__":
    main()
