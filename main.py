from flask import Flask, render_template, url_for, redirect, request, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, logout_user, current_user, login_required, LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import InputRequired, Length, Email
from flask_bcrypt import Bcrypt
from datetime import datetime
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hello'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
con = sqlite3.connect("data.db")
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS user (username TEXT, email TEXT, password TEXT)")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)], render_kw={"placeholder": "Email"})
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<List %r>' % self,id
    


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
            flash("Welcome to your account!", "warning")        
            return redirect(url_for('index2')) 
        else:   
            return '<h1>Invalid username or password</h1>'
    return render_template("index.html", form=form)    


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/reg', methods=['GET', 'POST'])
def reg():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data,  method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account successfully created!", "warning")
        return redirect(url_for('index'))
    
    return render_template("reg.html", form=form)


@app.route('/index2')
@login_required
def index2():
    return render_template("index2.html", name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



@app.route('/list_page', methods=['POST', 'GET'])
def list_page():
    if request.method == "POST":
        title = request.form['title']
        text = request.form['text']

        gr_list = List(title=title, text=text)

        try:
            db.session.add(gr_list)
            db.session.commit()
            return redirect('user_page')
        except:
            return "Error 404"
    else:
        return render_template('list_page.html')


@app.route('/user_page')
def user_page():
    lists = List.query.order_by(List.date.desc()).all()
    return render_template("user_page.html", lists=lists)


@app.route('/user_page/<int:id>')
def lists_full(id):
    grocery = List.query.get(id)
    return render_template("list_full.html", grocery=grocery)


@app.route('/user_page/<int:id>/del')
def list_delete(id):
    grocery = List.query.get_or_404(id)

    try:
        db.session.delete(grocery)
        db.session.commit()
        return redirect('/user_page')
    except:
        return "While deleting list became an error"


@app.route('/user_page/<int:id>/update', methods=['POST', 'GET'])
def list_update(id):
    grocery = List.query.get(id)
    if request.method == "POST":
        grocery.title = request.form['title']
        grocery.text = request.form['text']

        try:
            db.session.commit()
            return redirect('/user_page')
        except:
            return "While updating list became an error"
    else:
        return render_template('list_update.html', grocery=grocery)



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)
