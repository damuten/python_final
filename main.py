from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from flask_bcrypt import Bcrypt
from datetime import datetime

db = SQLAlchemy()
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = r"postgresql://postgres:011009650247@localhost:5432/final"

with app.app_context():
    db.init_app(app)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'secretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(
        min=4, max=50)], render_kw={"placeholder": "Email"})

    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<List %r>' % self,id


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


@app.route('/reg', methods=['GET', 'POST'])
def reg():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template("reg.html", form=form)


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(User.username == form.username.data).first()
        hashed_pwd = bcrypt.generate_password_hash(form.data["password"], 10)
        if user:
            if bcrypt.check_password_hash(hashed_pwd, user.password):
                login_user(user)
        return redirect(url_for('index2'))
    return render_template("index.html", form=form)


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/index2')
def index2():
    return render_template("index2.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)
