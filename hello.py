from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
#from forms import RegistrationForm, LoginForm
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gigliglgghv'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///site.db'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///lists.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

bootstrap = Bootstrap(app)
moment = Moment(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Lists(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    weeklytask = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    


    def __repr__(self):
        return f"Lists()"
        # return f"Lists('{self.weeklytask}','{self.monthlytask}')"
        # return'<Weeklytask %r' %self.id
        # return'<Monthlytask %r' %self.id

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    tasks = db.relationship('Tasks', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}','{self.email}','{self.image_file}')"

# create db Model
class Tasks(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    year_goal = db.Column(db.String(200))
    month_goal = db.Column(db.String(200))
    weekly_goal = db.Column(db.String(200))
    weekly_todo = db.Column(db.String(200))
    daily_todo = db.Column(db.String(200))
    future_todo = db.Column(db.String(200))
    notes =  db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
            # return f"Tasks()"
            return '<year_goal %r>' %self.id


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(),Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please use a different one.')

    def validate_email(self, email):
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please use a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')



@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method == "POST":
        if 'weeklytask' in request.form:
            weeklytask = request.form['weeklytask']
            new_weeklytask = Lists(weeklytask=weeklytask)

            try:
                db.session.add(new_weeklytask)
                db.session.commit()
                return redirect('/')
            except: 
                return "There was an error adding your list item"
        elif 'monthlytask' in request.form:
            monthytask = request.form['monthlytask']
            new_monthlytask = Lists(monthlytask=monthlytask)

            try:
                db.session.add(new_monthlytask)
                db.session.commit()
                return redirect('/')
            except: 
                return "There was an error adding your list item"
        else: return render_template("index.html", lists=lists)

    else:
        lists = Lists.query.order_by(Lists.date_created)
        return render_template("index.html", lists=lists)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data,password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user,remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash(f'Login unsuccessful. Please check email and password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    return render_template('account.html')

if __name__ == '__main__':
    app.run(debug=True)