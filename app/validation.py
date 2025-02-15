from datetime import datetime
import re
import unicodedata

def normalize_input(data):
    """Elimina espacios extras y normaliza caracteres."""
    return unicodedata.normalize('NFKD', data.strip())

def validate_email(email):
    """Valida que el email termine en @urosario.edu.co."""
    email = normalize_input(email)
    return email.endswith("@urosario.edu.co")

def validate_dob(dob):
    """Valida que el usuario tenga al menos 16 años."""
    try:
        dob = normalize_input(dob)
        birth_date = datetime.strptime(dob, "%Y-%m-%d")
        today = datetime.today()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        return age >= 16
    except ValueError:
        return False

def validate_user(user):
    """Valida que el nombre de usuario solo contenga letras y puntos."""
    user = normalize_input(user)
    return bool(re.fullmatch(r"^[a-zA-Z.]+$", user))

def validate_dni(dni):
    """Valida que el DNI sea numérico, tenga máximo 10 dígitos y comience con 1000000000."""
    dni = normalize_input(dni)
    return dni.isdigit() and len(dni) == 10 and dni.startswith("1")

def validate_pswd(pswd):
    """Valida que la contraseña cumpla con los requisitos de seguridad."""
    pswd = normalize_input(pswd)
    return (
        8 <= len(pswd) <= 35 and
        re.search(r"[a-z]", pswd) and
        re.search(r"[A-Z]", pswd) and
        re.search(r"\d", pswd) and
        re.search(r"[#*@\$%&\-!+=?]", pswd)
    )

def validate_name(name):
    """Valida que el nombre solo contenga letras y espacios."""
    name = normalize_input(name)
    return bool(re.fullmatch(r"^[a-zA-Z ]+$", name))
