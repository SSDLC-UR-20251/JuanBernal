from flask import render_template, redirect, url_for, session
from app import app
from app.encryption import decrypt_aes, ofuscar_dni
from app.reading import read_db
from app.encryption import *


# app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/deposit', methods=['GET'])
def deposit():

    return render_template('deposit.html')


@app.route('/register', methods=["GET", "POST"])
def register():
    return render_template('form.html')


@app.route('/login', methods=["GET"])
def login():
    return render_template("login.html")


@app.route('/edit_user/<email>', methods=['GET'])
def edit_user(email):

    db = read_db("db.txt")

    if email not in db:
        return redirect(url_for('records', message="Usuario no encontrado"))

    user_info = db[email]

    # ✅ Desencriptar el DNI antes de pasarlo a la plantilla
    dni_real = decrypt_dni(user_info['dni'], user_info['dni_nonce']) #desencriptar dni antes de ponerlo en el formulario de edit_user

    return render_template('edit_user.html', user_data=user_info, dni=dni_real, email=email)


# Formulario de retiro
@app.route('/withdraw', methods=['GET'])
def withdraw():
    email = session.get('email')
    print(email)
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))
    return render_template('withdraw.html', balance=current_balance)
