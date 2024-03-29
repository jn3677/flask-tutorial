from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required
from flaskr.db import get_db

bp = Blueprint('blog', __name__)

@bp.route('/')
def index():
    db = get_db()
    posts = db.execute(
        'SELECT p.id, title, body, created, author_id, username'
        'FROM post p JOIN user u ON p.author_id = u.id'
        'ORDER BY createde DESC'
    ).fetchall()
    return render_template('blog/index.html', posts=posts)

@bp.route('/create', methods=('GET','POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = None

        if not title:
            error = 'Title is required'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO post (title, body, author_id)'
                'VALUES (?, ?, ?)',(title, body, g.user['id'])
            )
            db.commit()
            return redirect( url_for('blog.index'))
        
    return render_template('blog/create.html')

# update and delete views will need to fetch a post by id and check if the author

def get_post(id, check_author=True):
    post = get_db().execute(
        'SELECT p.id, title, body, created, author_id, username'
        'FROM post p JOIN user u ON p.author_id = u.id'
        'WHERE p.id = ?',(id,)
    ).fetchone()

    if post is None:
        # abort() will raise a special exception that returns an HTTP status code
        # 404 not found
        abort(404, f"Post id {id} doesn't exist.")

    if check_author and post['author_id'] != g.user['id']:
        # 403 forbidden
        # check author is useful to show a post when the user is not modifying it
        abort(403)
    return post

# update takes argument id. That corresponds to the <int:id> in the route
# real url would look like /1/update, and Flask will capture the 1, ensure it's an int
# and pass it as the id argument. If you don't specify int: and instead do <id>, it will be a string
@bp.route('/<int:id>/update', methods=('GET','POST'))
def update(id):
    post = get_post(id);

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = None

        if not title:
            error = "Title is required"
        
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE post SET title = ?, body = ?'
                'WHERE id = ?', (title, body, id)
            )
            db.commit()
            return redirect(url_for('blog.index'))
    return render_template('blog/update.html', post=post)


@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_post(id)
    db = get_db()
    db.execute('DELETE FROM post WHERE id = ?',(id,))
    db.commit
    return redirect(url_for('blog.index'))