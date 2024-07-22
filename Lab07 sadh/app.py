from flask import Flask, render_template, request, redirect, url_for, flash, session
from config import Config
from extensions import db, bcrypt
import re

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt.init_app(app)

with app.app_context():
    db.create_all()

from models import User

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('secret_page'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already in use', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
        elif not re.search(r'[a-z]', password):
            flash('Password must contain at least one lowercase letter', 'error')
        elif not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter', 'error')
        elif not re.search(r'\d$', password):
            flash('Password must end with a number', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('thank_you'))
    return render_template('signup.html')

@app.route('/secret_page')
def secret_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('secretPage.html')

@app.route('/thank_you')
def thank_you():
    return render_template('thankyou.html')

if __name__ == '__main__':
    app.run(debug=True)
