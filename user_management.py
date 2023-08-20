"""
User management module will allow for user signup (with email verification),
login, logout, and a dashboard. Logout and dashboard show off
"""
from datetime import datetime
from dataclasses import dataclass
from random import choice as rand_choice
import re
from json import load as json_load
from string import ascii_letters, digits
from os.path import dirname, abspath, join, exists
from flask import Flask, render_template, redirect, url_for, flash, Blueprint, send_from_directory
from flask_mail import Mail, Message
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (LoginManager, UserMixin, login_user, login_required,
                         logout_user, current_user, fresh_login_required)

CURR_DIR = dirname(abspath(__file__))
TEMPLATES = join(CURR_DIR, "templates")

# set up to use user created pages IF possible
DASHBOARD_PAGE = "dashboard.html"
if not exists(join(TEMPLATES, DASHBOARD_PAGE)):
    DASHBOARD_PAGE = f"~{DASHBOARD_PAGE}"
INDEX_PAGE = "index.html"
if not exists(join(TEMPLATES, INDEX_PAGE)):
    INDEX_PAGE = f"~{INDEX_PAGE}"
LOGIN_PAGE = "login.html"
if not exists(join(TEMPLATES, LOGIN_PAGE)):
    LOGIN_PAGE = f"~{LOGIN_PAGE}"
SIGNUP_PAGE = "signup.html"
if not exists(join(TEMPLATES, SIGNUP_PAGE)):
    SIGNUP_PAGE = f"~{SIGNUP_PAGE}"
FORGOT_PAGE = "forgot.html"
if not exists(join(TEMPLATES, FORGOT_PAGE)):
    FORGOT_PAGE = f"~{FORGOT_PAGE}"
RECOVER_PAGE = "recover.html"
if not exists(join(TEMPLATES, RECOVER_PAGE)):
    RECOVER_PAGE = f"~{RECOVER_PAGE}"
EMAIL_UPDATE_PAGE = "update_email.html"
if not exists(join(TEMPLATES, EMAIL_UPDATE_PAGE)):
    EMAIL_UPDATE_PAGE = f"~{EMAIL_UPDATE_PAGE}"
PASSWORD_UPDATE_PAGE = "update_password.html"
if not exists(join(TEMPLATES, PASSWORD_UPDATE_PAGE)):
    PASSWORD_UPDATE_PAGE = f"~{PASSWORD_UPDATE_PAGE}"

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
    mail: Mail

class UserAlreadyExists(Exception):
    """Exception for a user already exists when trying to add a user"""

# blueprint the suer_management so that users can easily use this module
USER_MANAGEMENT_BP = Blueprint("user_management", __name__,
                               template_folder="templates",
                               static_folder="static")

DATABASE = SQLAlchemy()
LOGIN_MANGER = LoginManager()
MAIL = Mail()

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
MAX_FAILED_LOGIN = 5  # lock out at 5 failed logins
SPECIAL_CHARS = "!@#$%^&*(),.?:{}|<>"
PASSWORD_COMPLEXITY_ERROR = \
    (f"Password must contain at least one uppercase letter, one lowercase "
     "letter, one digit, and one special symbol [ {SPECIAL_CHARS} ].")

def create_app(database_path=join(CURR_DIR, ".login.db")):
    """Creates a full app for the code using this module

    Args:
        database_path (str, optional): The absolute path of the database.
                                       Defaults to the same dir as this file,
                                       with the name ".login.db"

    Raises:
        FileNotFoundError: the database dir or email config file not found

    Returns:
        AppWithUserManagement: dataclass with the full app members
    """
    # make an configure the flask app with database
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "Wow...oh so secret!!!"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:////{database_path}"
    # pylint: disable=unused-variable
    bootstrap = Bootstrap(app) # needed to use bootstrap templates
    # pylint: enable=unused-variable

    # set up email config - right now dictate where the json needs to be
    configure_mail(app, join(CURR_DIR, "mail_config.json"))
    MAIL.init_app(app)

    DATABASE.init_app(app)
    app.register_blueprint(USER_MANAGEMENT_BP, url_prefix="/UserManagement")

    # use login manager for easy user session management
    LOGIN_MANGER.init_app(app)
    LOGIN_MANGER.login_view = "login"

    full_app = AppWithUserManagement(app, DATABASE, database_path, MAIL)
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
            DATABASE.session.commit()

def configure_mail(app, config_file_path):
    """configures the app with the information to send emails

    Args:
        app (Flask): the flask app this is configuring
        config_file_path (str): the path to the mail_config.json
    """
    with open(config_file_path, 'r') as config_file:
        mail_config = json_load(config_file)

    app.config['MAIL_SERVER'] = mail_config.get('MAIL_SERVER')
    app.config['MAIL_PORT'] = mail_config.get('MAIL_PORT')
    username = mail_config.get('MAIL_USERNAME')
    app.config['MAIL_USERNAME'] = username
    app.config['MAIL_DEFAULT_SENDER'] = username
    app.config['MAIL_PASSWORD'] = mail_config.get('MAIL_PASSWORD')
    app.config['MAIL_USE_TLS'] = mail_config.get('MAIL_USE_TLS')
    app.config['MAIL_USE_SSL'] = mail_config.get('MAIL_USE_SSL')

### Common Fields Begin
EMAIL_FIELD = dict(
    label="Email",
    validators=[InputRequired(),
                Email(message="Invalid email"),
                Length(max=EMAIL_MAX)]
    )

def validate_password_complexity(form, field):
    """used as a FlaskForm validator on passwords to enforce strong passwords

    Raises:
        ValidationError: did not follow complexity rules
    """
    password = field.data
    if (
            # min one uppercase letter
            not re.search(r"[A-Z]", password) or
            # min one lowercase letter
            not re.search(r"[a-z]", password) or
            # min one digit
            not re.search(r"\d", password) or
            # min one special symbol
            not re.search(fr"[{SPECIAL_CHARS}]", password)
    ):
        raise ValidationError(PASSWORD_COMPLEXITY_ERROR)

def validate_username_complexity(form, field):
    """used as a FlaskForm validator on usernames to disallow characters

    Raises:
        ValidationError: did not follow rules
    """
    username = field.data
    allowed_pattern = r"^[a-zA-Z0-9_]+$"

    if not re.match(allowed_pattern, username):
        raise ValidationError("Username can only contain letters, numbers, and underscores.")

PASSWORD_FIELD = dict(
    label="Password",
    validators=[InputRequired(),
                Length(min=PASSWORD_MIN, max=PASSWORD_MAX),
                validate_password_complexity]
    )

PASSWORD_CONFIRM_FIELD = dict(
    label="Confirm Password",
    validators=[InputRequired(), EqualTo('password', message='Passwords must match')]
    )
### Common Fields End

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
    failed_logins = DATABASE.Column(DATABASE.Integer, default=0)
    validation_tokens = DATABASE.relationship("ValidationToken", back_populates="user")

class ValidationToken(UserMixin, DATABASE.Model):
    """A ValidationToken table for the database

    validation_token (str) - the validation token to compare against for the
                             validation link
    user_id (int) - a foreign key from the user table
    created_at (datetime) - a timestamp of when the token was created
    """
    validation_token = DATABASE.Column(DATABASE.String(TOKEN_LEN), unique=True,
                                       nullable=False, primary_key=True)
    user_id = DATABASE.Column(DATABASE.Integer, DATABASE.ForeignKey('user.id'))
    created_at = DATABASE.Column(DATABASE.DateTime, default=datetime.utcnow)
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
    password = PasswordField(**PASSWORD_FIELD)
    remember = BooleanField("remember me")

class RegisterForm(FlaskForm):
    """A FlaskForm for signing up

    email (str)
    username (str)
    password (str)
    password_confirm (str)
    """
    email = StringField(**EMAIL_FIELD)
    username = StringField(
        "User Name",
        validators=[InputRequired(),
                    Length(min=USERNAME_MIN, max=USERNAME_MAX),
                    validate_username_complexity]
        )
    password = PasswordField(**PASSWORD_FIELD)
    password_confirm = PasswordField(**PASSWORD_CONFIRM_FIELD)

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
    if user is None:
        flash("Invalid username or password.", "warning")
        return redirect(url_for("user_management.login"))

    # check to make sure they have verified their email
    if user.email_verified is False:
        validation_token = generate_verification_token(user)
        # resend verification email
        send_verification_email(user.email, validation_token)
        message = ("This email has not clicked their verification link.")
        flash(message, "warning")
        return redirect(url_for("user_management.login"))

    # check for brute force attacks
    message = "Account locked. An unlock email has been sent"
    if user.failed_logins >= MAX_FAILED_LOGIN:
        # previously locked due to brute force
        validation_token = generate_verification_token(user)
        send_unlock_email(user.email, validation_token)
        flash(message, "warning")
        return redirect(url_for("user_management.login"))
    if check_password_hash(user.password, form.password.data) is False:
        # wrong password, track
        user.failed_logins += 1
        DATABASE.session.commit()
        if not user.failed_logins >= MAX_FAILED_LOGIN:
            message = "Invalid username or password."
        else:
            # just now locked due to brute force
            validation_token = generate_verification_token(user)
            send_unlock_email(user.email, validation_token)
        flash(message, "warning")
        return redirect(url_for("user_management.login"))

    # reset attempts if successful
    user.failed_logins = 0
    DATABASE.session.commit()

    # login and go to user dashboard
    login_user(user, remember=form.remember.data)
    return redirect(url_for("user_management.dashboard"))

### Recovery Start
class ForgotForm(FlaskForm):
    """A FlaskForm for recovering account

    email (str)
    """
    email = StringField(**EMAIL_FIELD)

@USER_MANAGEMENT_BP.route("/forgot", methods=["GET", "POST"])
def forgot():
    """handles the forgot password/username (GET for form to submit, PUT to
    get email for recovery)

    Returns:
        str: the next page to display
    """
    form = ForgotForm()

    if not form.validate_on_submit():
        # it was a GET request
        return render_template(FORGOT_PAGE, form=form)

    # find user associated with email
    query_user = User.query.filter_by(email=form.email.data).first()
    if query_user is None:
        flash("An account is not associated with this email.", "warning")
        return redirect(url_for("user_management.forgot"))

    # gen token to send to email
    token = generate_verification_token(query_user)
    send_recover_email(query_user.email, token, query_user.username)
    flash("A recovery link has been sent to your email.", "warning")
    return redirect(url_for("user_management.login"))

class RecoverForm(FlaskForm):
    """A FlaskForm for changing password

    password (str)
    password_confirm (str)
    """
    password = PasswordField(**PASSWORD_FIELD)
    password_confirm = PasswordField(**PASSWORD_CONFIRM_FIELD)

@USER_MANAGEMENT_BP.route("/recover/<token>", methods=["GET", "POST"])
def recover_account(token):
    """handles the recovery of an account (GET form to change password,
    POST updating the password)

    Args:
        token (str): the token to verify the recovery

    Returns:
        str: the page to display next
    """
    form = RecoverForm()

    # make sure this is a valid token
    validation_token = (
        DATABASE.session
        .query(ValidationToken)
        .filter_by(validation_token=token)
        .first())

    if not validation_token:
        # token not in database
        flash("Invalid or expired link.", "warning")
        return redirect(url_for("user_management.login"))

    #valid token
    if not form.validate_on_submit():
        # it was a GET request
        return render_template(RECOVER_PAGE, form=form)

    # after verifying token and getting new password, update
    user = validation_token.user
    user.password = generate_password_hash(form.password.data, method="scrypt")
    # resetting password means its them to our knowledge since they accessed the email
    user.failed_logins = 0
    DATABASE.session.delete(validation_token)
    DATABASE.session.commit()
    flash("Password has been changed. Please login.", "warning")
    return redirect(url_for("user_management.login"))

def send_recover_email(email, token, username):
    """Sends the email with the recovery link

    Args:
        email (str): the email of the user
        token (str): the unique generated token
        username (str): the name of the user
    """
    verification_link = url_for("user_management.recover_account", token=token, _external=True)
    subject = "Recover Your Account"
    message = (f"Your username is: {username}\n\nClick the following link to "
               f"change your password your email: {verification_link}\n\nIf you"
               " did not request this, please ignore.")
    send_email(email, subject, message)
# Recovery End

# Unlock Start
@USER_MANAGEMENT_BP.route("/unlock/<token>")
def unlock_account(token):
    """Used when a user click on their unlock link

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
        flash("Invalid or expired link.", "warning")
    else:
        # verify the user with this token
        user = validation_token.user
        user.failed_logins = 0  # reset failed logins
        DATABASE.session.delete(validation_token)
        DATABASE.session.commit()
        flash("Account has been unlocked!", "warning")
    return redirect(url_for("user_management.login"))

def send_unlock_email(email, token):
    """Sends the email with the unlock link

    Args:
        email (str): the email of the user
        token (str): the unique generated token
    """
    verification_link = url_for("user_management.unlock_account", token=token, _external=True)
    subject = "Your account has been locked due to too many failed login attempts."
    message = (f"Click the following link to unlock: {verification_link}.\n"
               "If you did not cause this, we suggest changing your "
               "password as well.")
    send_email(email, subject, message)
# Unlock End

@USER_MANAGEMENT_BP.route("/dashboard")
@login_required
def dashboard():
    """displays the dashboard to the user

    Returns:
        str: the html of the dashboard
    """
    return render_template(DASHBOARD_PAGE, user=current_user)

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

def generate_verification_token(user):
    """gives a user a generation token if needed (this commits the changes)

    Args:
        user (User): the user that needs a validation token

    Returns:
        str: the token added to the user (or the current one it already has)
    """
    validation_token = (
        DATABASE.session
        .query(ValidationToken)
        .filter_by(user_id=user.id)
        .first())
    if validation_token is not None:
        # already has a token
        return validation_token.validation_token

    # needs a token - loop till we generate a token that has not been taken yet
    while True:
        token = generate_token(TOKEN_LEN)
        existing_token = ValidationToken.query.filter_by(validation_token=token).first()
        if existing_token is None:
            # found a unique token
            break

    # add and give back
    validation_token = ValidationToken(validation_token=token, user=user)
    DATABASE.session.add(validation_token)
    DATABASE.session.commit()
    return validation_token.validation_token

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
        flash("Invalid or expired link.", "warning")
    else:
        # verify the user with this token
        user = validation_token.user
        user.email_verified = True
        DATABASE.session.delete(validation_token)
        DATABASE.session.commit()
        flash("Email has been verified!", "warning")
    return redirect(url_for("user_management.login"))

def send_verification_email(email, token):
    """Sends the email with the verification link

    Args:
        email (str): the email of the user
        token (str): the unique generated token
    """
    verification_link = url_for("user_management.verify_email", token=token, _external=True)
    subject = "Verify Your Email"
    message = f"Click the following link to verify your email: {verification_link}"
    send_email(email, subject, message)

def send_email(email, subject, content):
    """send an email

    Args:
        email (str): the email address to send to
        subject (str): the email subject
        content (str): the body of the email
    """
    msg = Message(subject, recipients=[email])
    msg.body = content
    MAIL.send(msg)

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
        flash(f"Cannot create: {ex}", "warning")
        return redirect(url_for("user_management.login"))

    # get token send the email
    try:
        token = generate_verification_token(new_user)
    except UserAlreadyExists as ex:
        flash(f"Account Creation Failed: {ex}", "warning")
        return redirect(url_for("user_management.login"))
    send_verification_email(form.email.data, token)
    flash("New user has been created! Check your email to verify.", "warning")
    return redirect(url_for("user_management.login"))

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

class UpdateEmailForm(FlaskForm):
    """FlaskForm to change a users email
    """
    new_email = StringField(**EMAIL_FIELD)
    email_confirm = StringField(label="Confirm Password",
                                validators=[InputRequired(),
                                            EqualTo('new_email', message='Emails must match.')])
    password = PasswordField(**PASSWORD_FIELD)

class UpdatePasswordForm(FlaskForm):
    """FlaskForm to change a logged in users password
    """
    old_password = PasswordField(label="Old Password", validators=[InputRequired()])
    password = PasswordField(**PASSWORD_FIELD)
    password_confirm = PasswordField(**PASSWORD_CONFIRM_FIELD)

@USER_MANAGEMENT_BP.route("/update_email", methods=["GET", "POST"])
@fresh_login_required
def update_email():
    """updates a users email

    Returns:
        str: the html of the page to display net
    """
    form = UpdateEmailForm()

    if form.validate_on_submit():
        # POST
        user = current_user
        if check_password_hash(user.password, form.password.data):
            user.email = form.new_email.data
            DATABASE.session.commit()
            flash("Email updated successfully.", "success")
        else:
            flash("Incorrect password.", "warning")

    # GET
    return render_template(EMAIL_UPDATE_PAGE, form=form)

@USER_MANAGEMENT_BP.route("/update_password", methods=["GET", "POST"])
@fresh_login_required
def update_password():
    """updates a logged in users password

    Returns:
        str: the html of the page to display net
    """
    form = UpdatePasswordForm()

    if form.validate_on_submit():
        # POST
        user = current_user
        if check_password_hash(user.password, form.old_password.data):
            user.password = generate_password_hash(form.password.data, method="scrypt")
            DATABASE.session.commit()
            flash("Password updated successfully. Please log back in.", "success")
            logout_user()
            return redirect(url_for("user_management.login"))
        flash("Incorrect password.", "warning")

    # GET
    return render_template(PASSWORD_UPDATE_PAGE, form=form)

########################## END: SIGNING UP ###################################

if __name__ == "__main__":
    main()
