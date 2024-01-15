from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, default=False)
from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from .models import User

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('protected'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user is not None:
            flash('Email already exists.')
            return redirect(url_for('register'))
        user = User(email=email)
        user.password = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('protected'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password):
            flash('Invalid email or password')
            return redirect(url_for('login'))
        if not user.verified:
            flash('Your account has not been verified.')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('protected'))
    return render_template('login.html')

@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('index'))
    if current_user.confirm(token):
        flash('Your account has been confirmed.')
        return redirect(url_for('index'))
    else:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('login'))

def send_email(to, subject, template, **kwargs):
    msg = Message(subject, recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)