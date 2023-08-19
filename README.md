# User Management Module

starter code/html/css from: [this repo](https://github.com/PrettyPrinted/youtube_video_code/tree/master/2017/03/03/Build%20a%20User%20Login%20System%20With%20Flask-Login%2C%20Flask-WTForms%2C%20Flask-Bootstrap%2C%20and%20Flask-SQLAlchemy/building_user_login_system/finish)
- Modularized (while allowing users of the module to use their own page layouts if desired)
- Added email verification (with verification links)
- Added account recovery
- Flashed information to make errors more obvious

## Description

This is a module that can be used for user management for your Flask app. It will handle account creation (with verification links), login/logout with separate user sessions, forgot password, and brute force mitigation though locking the account after a certain amount of failed login attempts.

## Set-Up

1. Install the pip requirements
2. Use the template to create a "main_config.json" in the same level as the user_management.py with information for your email sending

## Testing as stand-alone

1. Complete the set-up above
2.
```sh
python3 user_management.py
```

Pages to test:
- /UserManagement/  This is the index page that will have links to login and sign up
- /UserManagement/login  This is the login page, which has a link for users to recover their account if they forgot their login
- /UserManagement/signup  This is the page for a user to sign up, and well send a verification link if they successfully sign up
- /UserManagement/dashboard  This is the users landing page after being logged in (NOTE: trying to access this page with out being logged in will bring you to the login page with a message saying you must be logged in)
- /UserManagement/logout  Can be accessed from the dashboard, and will log out the current user
- From the login page, test the forgot password feature (will send a link to recover their account)
- Try entering in the wrong password for an existing user multiple times to get a recovery email sent, and test the recover functionality

## Using this module for your own site

To use this with your own site:
1. Call create_app() at the top of your file (FULL_APP = create_app())
2. Define all your database tables (with relationships), routes, etc
3. At the bottom of your file (before the __name__ == "__main__") , create the relationships to the user management tables if needed. Example: User.categories = FULL_APP.database.relationship("Category", back_populates="user")
    NOTE: This must be done after te first 2 steps
4. Run the app only after other steps (FULL_APP.app.run())

### Using your own pages

In the templates directory, you can see that they start with a tilde. This is so that if you place a file in there without the tilde, it will use that one. This allows users of this module to create their own pages for this user management module.
