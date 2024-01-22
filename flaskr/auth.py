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
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?,?)",
                    (username,generate_password_hash(password))
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered"
            else:
                return redirect(url_for('auth.login'))