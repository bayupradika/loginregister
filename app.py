import os
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY  # Menggunakan secret_key dari config.py

# Konfigurasi database SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('base'))
        else:
            flash('Combination of username and password is incorrect.', 'danger')
    return render_template('login.html')


# Fungsi untuk menulis informasi user ke dalam file txt
def write_to_file(username, email):
    filename = 'registered_users.txt'  # Nama file txt untuk menyimpan informasi user

    try:
        # Membuka file dengan mode append ('a')
        with open(filename, 'a') as file:
            file.write(f"Username: {username}, Email: {email}\n")
    except IOError as e:
        # Menangani error jika ada masalah saat menulis ke file
        print(f"Error writing to file: {e}")

# Di dalam fungsi register()
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()

            # Panggil fungsi untuk menulis informasi user ke dalam file txt
            write_to_file(username, email)

            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()  # rollback transaksi yang gagal
            flash('Username or email already taken. Please choose another one.', 'danger')

    return render_template('register.html')

@app.route('/base')
def base():
    if 'user_id' in session:
        return render_template('base.html')
    else:
        flash('You need to login first.', 'warning')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
