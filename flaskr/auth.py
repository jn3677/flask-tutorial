# auth blueprint. Will have views to register new users and login/out

import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

#creates Blueprint named auth. Its defined here (__name__) and path prefix is /auth
#used for all the URLS associated with the blueprint
bp = Blueprint('auth',__name__,url_prefix='/auth')

# associate the URL /register with the register view function
# when flask recieves a request to /auth/register it will call the register view
# and use the return value as the response
@bp.route('/register', methods=('GET', 'POST'))
def register():
    # if the user submitted the form, request.method will be 'POST'
    if request.method == 'POST':
        # request.form is a special type of dict mapping submitted form keys and values
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Passowrd is required'
        
        if error is None:
            try:
                # takes am SQL query with ? place holders for any user input
                # and a tuple of values to replace the placeholders with
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?,?)",
                    (username,generate_password_hash(password))
                    # passwords shouln't be stored directly, use hash
                )
                # query modifies data so use db.commit() afterwards to save changes
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered"
            else:
                # once user is stored in database, redirect to login page
                return redirect(url_for('auth.login'))
        
        # if validation fails, the error is shown to the user
        flash(error)
    
    # when the user initlially navigates to auth/register, or there was an error
    # and html page will be shown with the registration form
    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        passowrd = request.form['password']
        db = get_db()
        error = None

        # fetches one row from query, if no rows match the query, returns None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password'
        
        if error is None:
            # session is a dict that stores data across requests
            # if validation succeeds, the user's id is stored in a new session
            # data is stored in a cookie that is sent to the browser, and browser
            # sends it back with subsequent requests. Flask securely signs the data
            # so that it can't be tampered with
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
            # basically stores the user_id in session so that application would
            # remember that user in subsequent requests
        
        flash(error)
    return render_template('auth/login.html')

# registers a function that runs before the view function, no matter what URL is requested
# load_logged_in_user checks if a user id is stored in the session and gets that user's data
# from the database, storing it on g.user, which lasts for the length of the request
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# requires authentication in other views
def login_required(view):
    # wraps the view that is passed in and returns new view function
    # new function checks if user is loaded and redirects to login otherwise
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        
        return view(**kwargs)
    
    return wrapped_view