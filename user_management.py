"""
User management module will allow for user signup (with email verification),
login, logout, and a dashboard. Logout and dashboard show off
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
from flask_login import (LoginManager, UserMixin, login_user, login_required,
                         logout_user, current_user)

CURR_DIR = dirname(abspath(__file__))
STATIC_DIR = join(CURR_DIR, "static")

# set up to use user created pages IF possible
DASHBOARD_PAGE = "dashboard.html"
if not exists(join(STATIC_DIR, DASHBOARD_PAGE)):
    DASHBOARD_PAGE = f"~{DASHBOARD_PAGE}"
INDEX_PAGE = "index.html"
if not exists(join(STATIC_DIR, INDEX_PAGE)):
    INDEX_PAGE = f"~{INDEX_PAGE}"
LOGIN_PAGE = "login.html"
if not exists(join(STATIC_DIR, LOGIN_PAGE)):
    LOGIN_PAGE = f"~{LOGIN_PAGE}"
SIGNUP_PAGE = "signup.html"
if not exists(join(STATIC_DIR, SIGNUP_PAGE)):
    SIGNUP_PAGE = f"~{SIGNUP_PAGE}"

def main():
    """called if this is the main python file"""
    full_app = create_app()
    init_db(full_app)
    full_app.app.run()

########################## START: SET UP APP ###################################

@dataclass
class AppWithUserManagement:
    """
    Is used to hold the app specific variables for easy passback in create_app()
    """
    app: Flask
    database: SQLAlchemy
    db_path: str

class UserAlreadyExists(Exception):
    """Exception for a user already exists when trying to add a user"""

# blueprint the suer_management so that users can easily use this module
USER_MANAGEMENT_BP = Blueprint("user_management", __name__,
                               template_folder="templates",
                               static_folder="static")

DATABASE = SQLAlchemy()
LOGIN_MANGER = LoginManager()

@LOGIN_MANGER.unauthorized_handler
def unauthorized_callback():
    """function to configure the login manager with

    Returns:
        str: the html of the page that should be displayed if a non-logged in
             user tried to access a page that requires a login
    """
    flash("You need to be logged in to access that page.", "warning")
    return redirect(url_for("user_management.login"))

# defines for bounds checking
USERNAME_MIN = 4
USERNAME_MAX = 20
PASSWORD_MIN = 8
PASSWORD_MAX = 30
EMAIL_MAX = 50
TOKEN_LEN = 32

def create_app(database_path=join(CURR_DIR, ".login.db")):
    """Creates a full app for the code using this module

    Args:
        database_path (str, optional): The absolute path of the database.
                                       Defaults to the same dir as this file,
                                       with the name ".login.db"

    Returns:
        _type_: _description_
    """
    # make an configure the flask app with database
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "Wow...oh so secret!!!"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:////{database_path}"
    # pylint: disable=unused-variable
    bootstrap = Bootstrap(app) # needed to use bootstrap templates
    # pylint: enable=unused-variable
    DATABASE.init_app(app)
    app.register_blueprint(USER_MANAGEMENT_BP, url_prefix="/UserManagement")

    # use login manager for easy user session management
    LOGIN_MANGER.init_app(app)
    LOGIN_MANGER.login_view = "login"

    full_app = AppWithUserManagement(app, DATABASE, database_path)
    return full_app

def init_db(full_app):
    """
    Initialized the database if it does not exist yet

    Args:
        full_app (AppWithUserManagement) - holds the information to initialize
    """
    if not exists(full_app.db_path):
        with full_app.app.app_context():
            DATABASE.create_all()

class User(UserMixin, DATABASE.Model):
    """A User table for the database

    id (int) - unique id for the user
    username (str)
    email (str)
    password (str)
    email_validated (bool)
    """
    id = DATABASE.Column(DATABASE.Integer, primary_key=True)
    username = DATABASE.Column(DATABASE.String(USERNAME_MAX), unique=True, nullable=False)
    email = DATABASE.Column(DATABASE.String(EMAIL_MAX), unique=True, nullable=False)
    password = DATABASE.Column(DATABASE.String(PASSWORD_MAX), nullable=False)
    email_verified = DATABASE.Column(DATABASE.Boolean, default=False)
    validation_tokens = DATABASE.relationship("ValidationToken", back_populates="user")

class ValidationToken(UserMixin, DATABASE.Model):
    """A ValidationToken table for the database

    validation_token (str) - the validation token to compare against for the
                             validation link
    user_id (int) - a foreign key from the user table
    """
    validation_token = DATABASE.Column(DATABASE.String(TOKEN_LEN), unique=True,
                                       nullable=False, primary_key=True)
    user_id = DATABASE.Column(DATABASE.Integer, DATABASE.ForeignKey('user.id'))
    user = DATABASE.relationship("User", back_populates="validation_tokens")

class LoginForm(FlaskForm):
    """A FlaskForm for logging in

    username (str)
    password (str)
    """
    username = StringField(
        "username",
        validators=[InputRequired(), Length(min=USERNAME_MIN, max=USERNAME_MAX)]
        )
    password = PasswordField(
        "password",
        validators=[InputRequired(), Length(min=PASSWORD_MIN, max=PASSWORD_MAX)]
        )
    remember = BooleanField("remember me")

class RegisterForm(FlaskForm):
    """A FlaskForm for signing up

    email (str)
    username (str)
    password (str)
    """
    email = StringField(
        "email",
        validators=[InputRequired(),
                    Email(message="Invalid email"),
                    Length(max=EMAIL_MAX)]
        )
    username = StringField(
        "username",
        validators=[InputRequired(), Length(min=USERNAME_MIN, max=USERNAME_MAX)]
        )
    password = PasswordField(
        "password",
        validators=[InputRequired(), Length(min=PASSWORD_MIN, max=PASSWORD_MAX)]
        )

@USER_MANAGEMENT_BP.route("/")
def index():
    """serves the index page

    Returns:
        str: the html of the page
    """
    return render_template(INDEX_PAGE)

@USER_MANAGEMENT_BP.route('/static/<path:filename>')
def serve_static(filename):
    """serves a file from the static dir of this blueprint

    Args:
        filename (str): the name of the file to get

    Returns:
        str: the contents of the page
    """
    return send_from_directory('static', filename)

########################## END: SET UP APP #####################################

########################## START: CURRENT USER OPERATIONS ######################

@LOGIN_MANGER.user_loader
def load_user(user_id):
    """loads a user be the user ID"""
    return DATABASE.session.get(User, user_id)

@USER_MANAGEMENT_BP.route("/login", methods=["GET", "POST"])
def login():
    """handles the login of a user for the front end

    Returns:
        str: the html page to display next (GET will be login page, POST will
             redirect to the dashboard)
    """
    form = LoginForm()

    if not form.validate_on_submit():
        # GET request
        return render_template(LOGIN_PAGE, form=form)

    # POST request - get the user and verify login info (and email validated)
    user = User.query.filter_by(username=form.username.data).first()
    if (user is None) or (check_password_hash(user.password, form.password.data) is False):
        return "<h1>Invalid username or password</h1>"
    if user.email_verified is False:
        # todo look at return
        return "<h1>Need to verify email before logging in. NEED TO HAVE AN OPTION TO RESEND</h1>"

    # login and go to user dashboard
    login_user(user, remember=form.remember.data)
    return redirect(url_for("user_management.dashboard"))

@USER_MANAGEMENT_BP.route("/dashboard")
@login_required
def dashboard():
    """displays the dashboard to the user

    Returns:
        str: the html of the dashboard
    """
    return render_template(DASHBOARD_PAGE, name=current_user.username)

@USER_MANAGEMENT_BP.route("/logout")
@login_required
def logout():
    """logs a user out

    Returns:
        str: the html page to redirect the user to
    """
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
    """Used when a user click on their verification link

    Args:
        token (str): the token embedded in the link

    Returns:
        str: the html page to display to the user
    """
    # get the token from the database
    validation_token = (
        DATABASE.session
        .query(ValidationToken)
        .filter_by(validation_token=token)
        .first())

    if not validation_token:
        # token not in database
        return "<h1>Invalid or expired token.</h1>"

    # verify the user with this token
    user = validation_token.user
    user.email_verified = True
    DATABASE.session.delete(validation_token)
    DATABASE.session.commit()
    return "<h1>Email has been verified!</h1>"


# todo create an email that will send this email out
# todo watch https://www.youtube.com/watch?v=vF9n248M1yk to get the info how to send it
def send_verification_email(email, token):
    """Sends the email with the verification link

    Args:
        email (str): the email of the user
        token (str): the unique generated token
    """
    verification_link = url_for("user_management.verify_email", token=token, _external=True)
    subject = "Verify Your Email"
    message = f"Click the following link to verify your email: {verification_link}"
    print(f"Email sent to {email} with verification link: {verification_link}")

@USER_MANAGEMENT_BP.route("/signup", methods=["GET", "POST"])
def signup():
    """Returns the page for the user signup

    Returns:
        str: the signup html
    """
    form = RegisterForm()

    if not form.validate_on_submit():
        # it was a GET request
        return render_template(SIGNUP_PAGE, form=form)

    # POST request - create the user
    try:
        new_user = add_user(form.username.data, form.password.data, form.email.data)
    except UserAlreadyExists as ex:
        return f"<h1>Cannot create: {ex}</h1>"

    # loop till we generate a token that has not been taken yet
    while True:
        token = generate_token(TOKEN_LEN)
        existing_token = ValidationToken.query.filter_by(validation_token=token).first()
        if existing_token is None:
            break
    validation_token = ValidationToken(validation_token=token, user=new_user)

    # save the changed and send the email
    try:
        DATABASE.session.add(validation_token)
        DATABASE.session.commit()
    except UserAlreadyExists as ex:
        return f"<h1>Account Creation Failed: {ex}</h1>"
    send_verification_email(form.email.data, token)
    return "<h1>New user has been created! Check your email to verify.</h1>"

def add_user(username, password, email, email_verified=False):
    """Adds a user to the User table of the database

    Args:
        username (str): the username of the user to add
        password (str): the password of the user
        email (str): the email of the user
        email_verified (bool, optional): Defaults to False.

    Raises:
        UserAlreadyExists: Email or Username is already used (the exception
                           string will have which one)

    Returns:
        User: the new user that was created if needed. If not, it has already
              been added to the database
    """
    # check that unique fields are going to be unique
    query_username = User.query.filter_by(username=username).first()
    query_email = User.query.filter_by(email=email).first()
    if query_username is not None:
        raise UserAlreadyExists("This username has already been taken")
    if query_email is not None:
        raise UserAlreadyExists("This email already has an account")

    # get the password hash (DO NOT save off actual passwords)
    hashed_password = generate_password_hash(password, method="scrypt")
    new_user = User(username=username,
                    email=email,
                    password=hashed_password,
                    email_verified=email_verified)

    # save changed
    DATABASE.session.add(new_user)
    DATABASE.session.commit()
    return new_user

########################## END: SIGNING UP ###################################

if __name__ == "__main__":
    main()
