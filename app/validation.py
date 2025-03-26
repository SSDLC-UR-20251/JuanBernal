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

class TestValidationFunctions(unittest.TestCase):
    
    def test_validate_email(self):
        self.assertTrue(validate_email("usuario@urosario.edu.co"))
        self.assertFalse(validate_email("usuario@gmail.com"))
        self.assertFalse(validate_email("usuario@urosario.com"))
        self.assertFalse(validate_email("usuario@urosario.edu"))
        self.assertFalse(validate_email("@urosario.edu.co"))
    
    def test_validate_dob(self):
        self.assertTrue(validate_dob("2000-01-01"))  # Mayor de 16
        self.assertFalse(validate_dob("2010-01-01")) # Menor de 16
    
    def test_validate_user(self):
        self.assertTrue(validate_user("sara.palacios"))
        self.assertFalse(validate_user("sara_palacios"))
        self.assertFalse(validate_user("sarapalacios"))
        self.assertFalse(validate_user("sara.palacios1"))
        self.assertFalse(validate_user("sara.palacios!"))  # No debe contener caracteres especiales
    
    def test_validate_dni(self):
        self.assertTrue(validate_dni("1000000001"))
        #self.assertFalse(validate_dni("9999999999"))
        self.assertFalse(validate_dni("10000000001"))
        self.assertFalse(validate_dni("abcdefg123"))
    
    def test_validate_name(self):
        self.assertTrue(validate_name("Sara"))
        self.assertTrue(validate_name("Palacios"))
        self.assertFalse(validate_name("Sara123"))
        self.assertFalse(validate_name("Sara_Palacios"))
        self.assertFalse(validate_name("Sara!"))
        self.assertFalse(validate_name("Sara Palacios"))  # No debe contener espacios
    
    def test_validate_password(self):
        self.assertTrue(validate_pswd("Passw0rd!"))  # Cumple con los requisitos
        self.assertFalse(validate_pswd("password"))  # Falta mayúscula, número y especial
        self.assertFalse(validate_pswd("PASSWORD1"))  # Falta minúscula y especial
        self.assertFalse(validate_pswd("Passw0rd"))  # Falta carácter especial
        self.assertFalse(validate_pswd("Pw1!"))  # Demasiado corta
        self.assertFalse(validate_pswd("A" * 36 + "1!"))  # Demasiado larga

if __name__ == "__main__":
    unittest.main()