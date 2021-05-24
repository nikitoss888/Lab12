import os
import random
import string

from flask import render_template, request, redirect, url_for, flash
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from flask import send_from_directory
from wtforms.validators import ValidationError, DataRequired, EqualTo

UPLOAD_FOLDER = 'static/pictures/albums'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'a really really really really long secret key'
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///albums.db"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://biosmlzpykmiun:b101919c25bef99a12483d0a79a77f0fc13c1a0ddf445c2641bc54b92a13b922@ec2-54-220-170-192.eu-west-1.compute.amazonaws.com:5432/d2dtcdb1cfq2ev"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'site_login'


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class User(db.Model, UserMixin):
    table_ame = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<{self.id}:{self.username}>"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Albums(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    short_text = db.Column(db.String(255), nullable=False)
    text = db.Column(db.Text, nullable=False)
    photo = db.Column(db.String(100), nullable=True)
    year = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Albums %r>' % self.id


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField()


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')


# Test urls
@app.route('/')
def start_redirect():
    return redirect(url_for('site_index'))


@app.route('/test')
def test():
    return render_template('site/test.html')


# @app.route('/hello-world')
# def hello_world():
#     return 'Hello World!'
#
#
# @app.route('/books/<genre>/')
# def books_genre(genre):
#     book_id = request.args.get('id')
#     return render_template('books/genre.html', genre=genre, id=book_id)


# Site urls
@app.route('/site')
def site_redirect():
    return redirect(url_for('site_index'))


@app.route('/site/')
def dash_site_redirect():
    return redirect(url_for('site_index'))


@app.route('/index')
def index_redirect():
    return redirect(url_for('site_index'))


@app.route('/site/index')
def site_index():
    return render_template('site/index.html')


@app.route('/login')
def login_redirect():
    return redirect(url_for('site_login'))


@app.route('/register')
def register_redirect():
    return redirect(url_for('site_register'))


@app.route('/site/register', methods=['GET', 'POST'])
def site_register():
    if current_user.is_authenticated:
        return redirect(url_for('site_index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('site_login'))
    return render_template('site/register.html', title='Register', form=form)


@app.route('/site/login', methods=['post', 'get'])
def site_login():
    if current_user.is_authenticated:
        return redirect(url_for("site_index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('site_index'))

        flash("Invalid username/password", 'error')
        return redirect(url_for('site_login'))
    return render_template('site/login.html', form=form)


@app.route('/site/logout/')
@login_required
def site_logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('site_index'))


@app.route('/site/about-project')
def site_about_project():
    return render_template('site/about_project.html')


@app.route('/site/history')
def site_history():
    return render_template('site/history.html')


# Albums CRUD
@app.route('/albums')
def albums_redirect():
    return redirect(url_for('albums_index'))


@app.route('/albums/index')
@login_required
def albums_index():
    albums = Albums.query.order_by('title').all()
    return render_template('albums/index.html', albums=albums)


@app.route('/albums/create', methods=['POST', 'GET'])
def album_create():
    if request.method == 'POST':
        title = request.form['title']
        short_text = request.form['short_text']
        text = request.form['text']
        photo = request.files['photo']
        year = request.form['year']
        if photo and allowed_file(photo.filename):
            ext = '.' + photo.filename.split('.')[-1]
            filename = ''.join(random.choice(string.ascii_letters) for i in range(30)) + ext
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            return render_template('albums/create.html')

        album = Albums(title=title, short_text=short_text, text=text, photo=filename, year=year)
        try:
            db.session.add(album)
            db.session.commit()
            return redirect(url_for('albums_view', id=album.id))
        except:
            return 'Сталася помилка'
    else:
        return render_template('albums/create.html')


@app.route('/albums/view/<int:id>')
def albums_view(id):
    album = Albums.query.get(id)
    return render_template('albums/view.html', album=album)


@app.route('/pictures/albums/<string:filename>')
def photos(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/albums/edit/<int:id>', methods=['POST', 'GET'])
@login_required
def album_edit(id):
    album = Albums.query.get(id)
    if request.method == 'POST':
        old_photo = album.photo
        album.title = request.form['title']
        album.short_text = request.form['short_text']
        album.text = request.form['text']

        album.year = request.form['year']
        if os.path.isfile(app.config['UPLOAD_FOLDER'] + "/" + old_photo):
            os.remove(app.config['UPLOAD_FOLDER'] + "/" + old_photo)

        if album.photo and allowed_file(album.photo):
            ext = '.' + album.photo.split('.')[-1]
            filename = ''.join(random.choice(string.ascii_letters) for i in range(30)) + ext
            request.files['photo'].save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            album.photo = filename
        else:
            return render_template('albums/create.html')

        try:
            db.session.commit()
            return redirect(url_for('albums_view', id=id))
        except:
            return 'Сталася помилка'
    else:
        return render_template('albums/edit.html', album=album)


@app.route('/albums/delete/<int:id>')
@login_required
def albums_delete(id):
    album = Albums.query.get_or_404(id)
    try:
        db.session.delete(album)
        db.session.commit()
        return redirect(url_for('albums_index'))
    except:
        return 'Сталася помилка'


@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)


def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


if __name__ == '__main__':
    app.run()
    with app.test_request_context('/api'):
        print(url_for('/api', _external=True))
