import secrets
import os
from PIL import Image
from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
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


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}','{self.email}','{self.image_file}')"

class Yearly_Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    date_create = db.Column(db.DateTime,default=datetime.utcnow)

    def __repr__(self):
                return f"Yearly_Tasks()"

class Monthly_Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    date_create = db.Column(db.DateTime,default=datetime.utcnow)

    def __repr__(self):
                return f"Montly_Tasks()"

class Weekly_Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    date_create = db.Column(db.DateTime,default=datetime.utcnow)

    def __repr__(self):
                return f"Weekly_Tasks()"

class Weekly_Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    date_create = db.Column(db.DateTime,default=datetime.utcnow)

    def __repr__(self):
                return f"Weekly_Todo()"

class Daily_Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    date_create = db.Column(db.DateTime,default=datetime.utcnow)

    def __repr__(self):
                return f"Daily_Todo()"

class Future_Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    date_create = db.Column(db.DateTime,default=datetime.utcnow)

    def __repr__(self):
                return f"Future_Todo()"

class Memo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    date_create = db.Column(db.DateTime,default=datetime.utcnow)

    def __repr__(self):
                return f"Memo()"



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

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(),Email()])
    picture = FileField('Profile Picture', validators=[FileAllowed(['jpg','png'])])
    submit = SubmitField('Update')

    def validate_username(self,username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please use a different one.')

    def validate_email(self, email):
         if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please use a different one.')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Query the Tasks table to get all the tasks of the logged in user (match ID)
# Query the Table obtained in step1 to get the tasks specific to the table name for each table ( i.e. query it 7 times for each table )
# Display the result you get for each of the 7 queries in specific table in the front-end 


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == "POST":
        if 'yearlygoal' in request.form:
            yearlygoal_name = request.form['yearlygoal']
            new_yearlygoal = Yearly_Tasks(title=yearlygoal_name)
            # push to db
            try:
                db.session.add(new_yearlygoal)
                db.session.commit()
                return redirect(url_for('index'))
            except:
                return "There was an error adding your yearly goal"
        elif 'monthlygoal' in request.form:
            monthlygoal_name = request.form['monthlygoal']
            new_monthlygoal = Monthly_Tasks(title=monthlygoal_name)
            # push to db
            try:
                db.session.add(new_monthlygoal)
                db.session.commit()
                return redirect(url_for('index'))
            except:
                return "There was an error adding your monthly goal"
        elif 'weeklygoal' in request.form:
            weeklygoal_name = request.form['weeklygoal']
            new_weeklygoal = Weekly_Tasks(title=weeklygoal_name)
            # push to db
            try:
                db.session.add(new_weeklygoal)
                db.session.commit()
                return redirect(url_for('index'))
            except:
                return "There was an error adding your weekly goal"
        elif 'weeklytodo' in request.form:
            weeklytodo_name = request.form['weeklytodo']
            new_weeklytodo = Weekly_Todo(title=weeklytodo_name)
            # push to db
            try:
                db.session.add(new_weeklytodo)
                db.session.commit()
                return redirect(url_for('index'))
            except:
                return "There was an error adding your weekly to-do item"
        elif 'dailytodo' in request.form:
            dailytodo_name = request.form['dailytodo']
            new_dailytodo = Daily_Todo(title=dailytodo_name)
            # push to db
            try:
                db.session.add(new_dailytodo)
                db.session.commit()
                return redirect(url_for('index'))
            except:
                return "There was an error adding your daily to-do item"
        elif 'futuretodo' in request.form:
            futuretodo_name = request.form['futuretodo']
            new_futuretodo = Future_Todo(title=futuretodo_name)
            # push to db
            try:
                db.session.add(new_futuretodo)
                db.session.commit()
                return redirect(url_for('index'))
            except:
                return "There was an error adding your future to-do item"
        elif 'memo' in request.form:
            memo_name = request.form['memo']
            new_memo = Memo(title=memo_name)

            try:
                db.session.add(new_memo)
                db.session.commit()
                return redirect(url_for('index'))
            except:
                "return there was an error adding your note"
    else:
        yearlygoals = Yearly_Tasks.query.order_by(Yearly_Tasks.date_create)
        monthlygoals = Monthly_Tasks.query.order_by(Monthly_Tasks.date_create)
        weeklygoals = Weekly_Tasks.query.order_by(Weekly_Tasks.date_create)
        weeklytodos = Weekly_Todo.query.order_by(Weekly_Todo.date_create)
        dailytodos = Daily_Todo.query.order_by(Daily_Todo.date_create)
        futuretodos = Future_Todo.query.order_by(Future_Todo.date_create)
        memos = Memo.query.order_by(Memo.date_create)
        return render_template('index.html', yearlygoals=yearlygoals, monthlygoals=monthlygoals, weeklygoals=weeklygoals, weeklytodos=weeklytodos, dailytodos=dailytodos, futuretodos=futuretodos, memos=memos)

@app.route('/delete/<int:id>')
def delete(id):
    item_to_delete = Yearly_Tasks.query.get_or_404(id)

    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was a problem deleting that item"

@app.route('/delete2/<int:id>')
def delete2(id):
    item_to_delete = Monthly_Tasks.query.get_or_404(id)

    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was a problem deleting that item"

@app.route('/delete3/<int:id>')
def delete3(id):
    item_to_delete = Weekly_Tasks.query.get_or_404(id)

    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was a problem deleting that item"

@app.route('/delete4/<int:id>')
def delete4(id):
    item_to_delete = Weekly_Todo.query.get_or_404(id)

    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was a problem deleting that item"

@app.route('/delete5/<int:id>')
def delete5(id):
    item_to_delete = Daily_Todo.query.get_or_404(id)

    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was a problem deleting that item"

@app.route('/delete6/<int:id>')
def delete6(id):
    item_to_delete = Future_Todo.query.get_or_404(id)

    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was a problem deleting that item"

@app.route('/delete7/<int:id>')
def delete7(id):
    item_to_delete = Memo.query.get_or_404(id)

    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was a problem deleting that item"


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

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('You have upated your account.', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/'+current_user.image_file)
    return render_template('account.html', image_file = image_file, form=form)

if __name__ == '__main__':
    app.run(debug=True)