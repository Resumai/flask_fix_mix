from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy import Column, Integer, String
# from forms import RegistrationForm

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo
from string import punctuation as valid_symbols





app = Flask(__name__)
app.secret_key = 'secret_key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Change the database URI as per your needs
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

bcrypt = Bcrypt(app)

class User(UserMixin, db.Model):
    id = Column(Integer, primary_key=True)
    username = Column(String(20), unique=True, nullable=False)
    password = Column(String(60), nullable=False)


class CustomPasswordValidator():
    def __init__(self):
        self.message = 'Password must have at least one upper letter, one lower letter, one symbol, one number and no space.'

    def __call__(self, form, field):
        text : str = field.data
        is_any_upper = any(c.isupper() for c in text)
        is_any_lower = any(c.islower() for c in text)
        is_any_number = any(c.isdigit() for c in text)
        is_no_space = not any(c.isspace() for c in text)
        is_any_symbol = any(c in valid_symbols for c in text)
        if not all([is_any_upper, is_any_lower, is_any_number, is_no_space, is_any_symbol]):
            raise ValidationError(self.message)


class RegistrationForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField(
        'Password:', 
        validators=[
            DataRequired(), 
            Length(min=6, max=20), 
            CustomPasswordValidator()
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password:', 
        validators=[
            DataRequired(), 
            EqualTo('password', message='Passwords must match')
        ]
    )

    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Login')



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    if current_user.is_authenticated:
        username = current_user.username
    else:
        username = None
    return render_template('index.html', username=username)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # if request.method == 'POST':
    #     username = request.form['username']
    #     password = request.form['password']
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('register.html', message='Username already exists')
        new_user = User(username=username, password=bcrypt.generate_password_hash(password).decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # if request.method == 'POST':
        # username = request.form['username']
        # password = request.form['password']
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            return render_template('login.html', message='Invalid username or password')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)