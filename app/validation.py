from datetime import datetime
import re

import unicodedata


def normalize_input(data):
    if isinstance(data, str):
        # Normalizar el texto a la forma canónica
        data = unicodedata.normalize('NFKD', data)
        # Convertir a minúsculas y eliminar espacios en blanco
        data = data.strip().lower()
    return data


# valido el email
def validate_email(email):
    email = normalize_input(email)
    pattern = r'^[a-zA-Z0-9._%+-]+@urosario\.edu\.co$' #concatena @urosario.edu.co al final del patron
    return re.match(pattern, email) is not None


# valido la edad
def validate_dob(dob):
    birth_date = datetime.strptime(dob, "%Y-%m-%d") # dob manipulable
    today = datetime.today()
    age = today.year - birth_date.year 

    if (today.month, today.day) < (birth_date.month, birth_date.day): #verifica la edad respecto al tiempo actual ej: cumple en dic 
        age -= 1

    return age > 16 #edad mayor a 16 años


# valido el usuario
def validate_user(user):
    patron = r'^[a-zA-Z]+\.[a-zA-Z]+$' #\. es para la separación de nombres por .
    return bool(re.fullmatch(patron, user))


# valido el dni
def validate_dni(dni):
    patron = r'^\d{10}$' #\d = digitos, {10} = cifras
    return bool(re.fullmatch(patron, dni))


# valido la contraseña
def validate_pswd(pswd):
#              1<minusculas, 1<mayusculas, 1<num, 1<especial, 8-35 caracteres
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#*@\$%&\-!+=?])[A-Za-z\d#*@\$%&\-!+=?]{8,35}$'
    return bool(re.fullmatch(pattern, pswd))

def validate_name(name):
    return bool(re.fullmatch(r'^[a-zA-Z]+$', name))
