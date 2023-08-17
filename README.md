# user_management_site
Module for user management for a flask website

starter code/html/css from: [this repo](https://github.com/PrettyPrinted/youtube_video_code/tree/master/2017/03/03/Build%20a%20User%20Login%20System%20With%20Flask-Login%2C%20Flask-WTForms%2C%20Flask-Bootstrap%2C%20and%20Flask-SQLAlchemy/building_user_login_system/finish)
- Modularized (while allowing users of the module to use their own page layouts if desired)
- Added email verification (with verification links)
- Added account recovery
- Flashed information to make errors more obvious

# things to do
- account lock out if they try to brute force...
- the actual sending of the verification link
- make this actual README lol
    - add a readme saying how you use it as a submole
		- replacing the default dashboard (If I give someone access to use this as a submoudle, I need to make sure that I only give them pull ability. I dont want them writing their dashboard to my repo)
        - explain the ~ for tester html pages (should I do this through the create_app() so they can use their own login and set up?)