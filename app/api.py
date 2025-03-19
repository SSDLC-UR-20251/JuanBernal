from datetime import datetime, timedelta
import time
from app.validation import *
from app.reading import *
from flask import request, jsonify, redirect, url_for, render_template, session, make_response, flash
from app import app
from app.encryption import *

app.secret_key = 'your_secret_key'

# 🔐 Variables Globales para Control de Intentos
MAX_INTENTOS = 3
TIEMPO_BLOQUEO = 300  # 5 minutos en segundos
usuarios_estado = {}  # { "usuario": { "intentos": 0, "tiempoBloqueo": 0 } }



@app.route('/api/users', methods=['POST'])
def create_record():
    data = request.form
    email = data.get('email')
    username = data.get('username')
    nombre = data.get('nombre')
    apellido = data.get('Apellidos')
    password = data.get('password')
    dni = data.get('dni')
    dob = data.get('dob')


    errores = []


    # Validaciones
    if not validate_email(email):
        errores.append("Email inválido")
    if not validate_pswd(password):
        errores.append("Contraseña inválida")
    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")


    if errores:
        return render_template('form.html', error=errores)

    email = normalize_input(email)

    # Encriptar la contraseña con hashing y salt
    password_hash, salt = hash_with_salt(password)

    # dni encriptado
    dni_encrypted, dni_nonce = encrypt_dni(dni)


    db = read_db("db.txt")
    db[email] = {
        'nombre': normalize_input(nombre),
        'apellido': normalize_input(apellido),
        'username': normalize_input(username),
        'password_hash': password_hash,#hash
        "salt": salt,#hash salt
        "dni": dni_encrypted, #dni encriptado
        "dni_nonce": dni_nonce, #dni nonce
        'dob': normalize_input(dob),
        "role": "user"
    }

    write_db("db.txt", db)
    return redirect("/login")


# Endpoint para el login
@app.route('/api/login', methods=['POST'])
def api_login():
    email = normalize_input(request.form.get('email', ''))
    password = request.form.get('password', '')

    #print(f"📩 Email recibido: {email}")  # Debug: Ver email recibido
    #print(f"🔑 Password recibido: {password}")  # Debug: Ver password recibido

    db = read_db("db.txt")

    # Verificar si el usuario está bloqueado
    if email in usuarios_estado:
        estado = usuarios_estado[email]
        if estado["tiempoBloqueo"] > time.time():
            tiempo_restante = int((estado["tiempoBloqueo"] - time.time()) / 60)
            return render_template('login.html', error=f"Cuenta bloqueada. Intenta en {tiempo_restante} minutos.")

    # Verificar si el usuario existe en la BD
    if email in db:
        stored_salt = db[email]["salt"]
        stored_hash = db[email]["password_hash"]

        #print(f"🗄 Stored Hash en BD: {stored_hash}")  # Debug
        #print(f"🧂 Stored Salt en BD: {stored_salt}")  # Debug

        # Verificar la contraseña
        if verify_password(stored_hash, password, stored_salt):
            session['role'] = db[email]['role']
            session['email'] = email
            usuarios_estado[email] = {"intentos": 0, "tiempoBloqueo": 0}  # Reset intentos
            print("✅ Login exitoso!")  # Debug
            return redirect(url_for('customer_menu'))
        else:
            print("❌ Contraseña incorrecta!")  # Debug

    # ❌ Si las credenciales son incorrectas
    if email not in usuarios_estado:
        usuarios_estado[email] = {"intentos": 0, "tiempoBloqueo": 0}

    usuarios_estado[email]["intentos"] += 1
    if usuarios_estado[email]["intentos"] >= MAX_INTENTOS:
        usuarios_estado[email]["tiempoBloqueo"] = time.time() + TIEMPO_BLOQUEO
        return render_template('login.html', error="Cuenta bloqueada por múltiples intentos fallidos.")

    return render_template('login.html', error="Credenciales inválidas.")



# Página principal del menú del cliente
@app.route('/customer_menu')
def customer_menu():
    if 'email' not in session:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)

    email = session.get('email')
    db = read_db("db.txt")
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))
    last_transactions = transactions.get(email, [])[-5:]
    message = request.args.get('message', '')
    error = request.args.get('error', 'false').lower() == 'true'
    return render_template('customer_menu.html',
                           message=message,
                           nombre=db.get(email)['nombre'],
                           balance=current_balance,
                           last_transactions=last_transactions,
                           error=error)


# Endpoint para leer un registro
@app.route('/records', methods=['GET'])
def read_record():

    db = read_db("db.txt")
    user_email = session.get('email')
    user_role = session.get('role')    # Obtener el rol del usuario actual
    user = db.get(user_email, None)
    message = request.args.get('message', '')

    # 📄 Filtrar registros: Admin ve todos, usuarios solo su propio registro
    if user_role == 'admin':
        filtered_users = db  # Admin ve todos
    else:
        filtered_users = {user_email: db.get(user_email)} if user_email in db else {}


    # 🔐 Descifrar y ofuscar DNI antes de renderizar
    for email, user_data in filtered_users.items():
        if "dni" in user_data and "dni_nonce" in user_data:  # Asegurar que los datos existen
            dni_real = decrypt_dni(user_data["dni"], user_data["dni_nonce"])  # Descifrar
            user_data["dni"] = f"****{dni_real[-4:]}"  # Mostrar solo los últimos 4 dígitos

    return render_template('records.html',
                           users=filtered_users,
                           role=user_role,
                           message=message)




@app.route('/update_user/<email>', methods=['POST'])
def update_user(email):
    # Leer la base de datos de usuarios
    db = read_db("db.txt")

    if email not in db:
        return redirect(url_for('read_record', message="Usuario no encontrado")) # verificar que el usuario que realiza la solicitud existe en la base de datos
        

    #input formulario actualización
    username = request.form['username']
    dni = request.form['dni']
    dob = request.form['dob']
    nombre = request.form['nombre']
    apellido = request.form['apellido']

    errores = []

    # Validaciones
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('edit_user.html',
                               user_data=db[email],
                               email=email,
                               error=errores)

    
    db[email]['username'] = normalize_input(username)
    db[email]['nombre'] = normalize_input(nombre)
    db[email]['apellido'] = normalize_input(apellido)
    db[email]['dni'], new_nonce = encrypt_dni(dni)
    db[email]['dob'] = normalize_input(dob)

    # verificar si toca cambiar el nonce
    if new_nonce != db[email]['dni_nonce']:
        db[email]['dni_nonce'] = new_nonce

    write_db("db.txt", db)

    # Capturar preferencia de modo oscuro
    darkmode = "dark" if request.form.get('darkmode') else "light"
    
    # Guardar la preferencia del modo oscuro en una cookie segura
    response = make_response(redirect(url_for('read_record', message="Información actualizada correctamente")))
    response.set_cookie('darkmode', darkmode, secure=True, httponly=False, samesite='Lax')


    # Redirigir con un mensaje de éxito
    return response


@app.route('/api/delete_user/<email>', methods=['GET'])
def delete_user(email):

    if session.get('role') == 'admin':
        db = read_db("db.txt")

        if email not in db:
            return redirect(url_for('read_record', message="Usuario no encontrado"))

        del db[email]

        write_db("db.txt", db)

        return redirect(url_for('read_record', message="Usuario eliminado"))
    else:
        return redirect(url_for('read_record', message="No autorizado"))

# Endpoint para depósito
@app.route('/api/deposit', methods=['POST'])
def api_deposit():
    if 'email' not in session:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)

    deposit_balance = request.form['balance']
    deposit_email = session.get('email')

    db = read_db("db.txt")
    transactions = read_db("transaction.txt")

    # Verificamos si el usuario existe
    if deposit_email in db:
        # Guardamos la transacción
        transaction = {"balance": deposit_balance, "type": "Deposit", "timestamp": str(datetime.now())}

        # Verificamos si el usuario tiene transacciones previas
        if deposit_email in transactions:
            transactions[deposit_email].append(transaction)
        else:
            transactions[deposit_email] = [transaction]
        write_db("transaction.txt", transactions)

        return redirect(url_for('customer_menu', message="Depósito exitoso"))

    return redirect(url_for('customer_menu', message="Email no encontrado"))


# Endpoint para retiro
@app.route('/api/withdraw', methods=['POST'])
def api_withdraw():
    email = session.get('email')
    password = request.form['password']
    amount = float(request.form['balance'])

    if amount <= 0:
        return redirect(url_for('customer_menu',
                                message="La cantidad a retirar debe ser positiva",
                                error=True))

    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))

    if amount > current_balance:
        return redirect(url_for('customer_menu',
                                message="Saldo insuficiente para retiro",
                                error=True))

    transaction = {"balance": -amount, "type": "Withdrawal", "timestamp": str(datetime.now())}

    #validar contraseña
    db = read_db("db.txt")

    if email in db:
        stored_salt = db[email]["salt"]
        stored_hash = db[email]["password_hash"]

        if not verify_password(stored_hash, password, stored_salt):
            return redirect(url_for('customer_menu',
                                message="Contraseña incorrecta",
                                error=True))

    if email in transactions:
        transactions[email].append(transaction)
    else:
        transactions[email] = [transaction]

    write_db("transaction.txt", transactions)

    return redirect(url_for('customer_menu',
                            message="Retiro exitoso",
                            error=False))

"""@app.before_request
def verify_session():
    if request.endpoint not in ["login", "api_login", "register", "api_users"]:# Excluimos el login y archivos estáticos para que no redirija en estas rutas
        if 'email' not in session: # Si no hay una sesión activa
            flash("Tu sesión ha expirado. Por favor, inicia sesión nuevamente.", "error")
            return redirect(url_for('login'))"""

@app.route('/logout') 
def logout():
    session.clear() #eliminamos los datos de la session actual
    return redirect(url_for('login')) #redirigimos a la página de login

#Configuración de la duración máxima de una sesión
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

@app.before_request
def renew_session():
    session.permanent = True