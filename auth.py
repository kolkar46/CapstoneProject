import os

from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, send_file
from flask_login import UserMixin, LoginManager, login_required, current_user, logout_user, login_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy()
db.init_app(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class User(UserMixin, db.Model):
    id = db.Column(db.INTEGER, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(50), nullable=False)


with app.app_context():
    db.create_all()


@app.route("/")
def pilot():
    logout_user()
    return render_template("pilot.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
        # return render_template('login.html')

    return render_template('login.html')


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("pilot"))


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        passw = request.form.get("password")
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already taken','error')
        else:
            hashed_pass = generate_password_hash(passw, method="pbkdf2:sha256", salt_length=8)
            new_user = User(username=username, password=hashed_pass, email=email)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("home"))
    return render_template("signup.html")


@app.route("/home")
@login_required
def home():
    return render_template("home.html", name=current_user.username)


@app.route("/download")
@login_required
def download():
    return send_file('static/files/sample.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5010)
