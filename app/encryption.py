from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64

def fixed_key(): # convertir KEY fija a bytes
    key_str = "secDevCycle2025_1"
    hash_obj = SHA256.new(key_str.encode())
    return hash_obj.digest()[:16]

def encrypt_dni(dni):
    """Cifra el DNI usando AES y devuelve el texto cifrado junto con el nonce."""
    KEY = fixed_key()

    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(dni.encode())

    return base64.b64encode(ciphertext).decode(), base64.b64encode(cipher.nonce).decode()

def decrypt_dni(ciphertext_b64, nonce_b64):
    """Descifra el DNI almacenado en la base de datos."""
    KEY = fixed_key()

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()



def verify_password(stored_hash, entered_password, stored_salt):
    """Verifica si la contraseña ingresada coincide con el hash almacenado."""
    salt_bytes = bytes.fromhex(stored_salt)  # Convertir la salt a bytes
    password_bytes = salt_bytes + entered_password.encode() 
    hash_obj = SHA256.new()
    hash_obj.update(password_bytes)

    entered_hash = hash_obj.hexdigest()

    
    # 🔍 Depuración
    print("\n--- Verificación de Contraseña ---")
    print(f"Stored Hash: {stored_hash}")
    print(f"Generated Hash: {entered_hash}")
    print(f"Salt Used: {stored_salt}")
    print("----------------------------------\n")

    return entered_hash == stored_hash  # Retorna True si coinciden

def hash_with_salt(password):
    """Genera un hash SHA-256 de la contraseña con una nueva salt."""
    salt = get_random_bytes(16)  # Generar nueva salt de 16 bytes
    password_bytes = salt + password.encode()
    hash_obj = SHA256.new()
    hash_obj.update(password_bytes)

    return hash_obj.hexdigest(), salt.hex()  # Retorna el hash y la salt como hexadecimal



def decrypt_aes(texto_cifrado_str, nonce_str, clave):
    # Convertir el texto cifrado y el nonce de cadena de texto a bytes
    texto_cifrado = bytes.fromhex(texto_cifrado_str)
    nonce = bytes.fromhex(nonce_str)

    # Crear un objeto AES con la clave y el nonce proporcionados
    cipher = AES.new(clave, AES.MODE_EAX, nonce=nonce)

    # Descifrar el texto
    texto_descifrado = cipher.decrypt(texto_cifrado)

    # Convertir los bytes del texto descifrado a una cadena de texto
    return texto_descifrado.decode()


def compare_salt(text, hash, salt):
    salt = bytes.fromhex(salt)
    # Convertir el texto en claro a bytes
    texto_bytes = text.encode('utf-8')
    # Crear un objeto de hash SHA-256
    hash_obj = SHA256.new()
    # Agregar la sal y el texto plano al hash
    hash_obj.update(salt)
    hash_obj.update(texto_bytes)
    # Calcular el hash final
    hash_result = hash_obj.digest()
    # convertimos a hex
    final = hash_result.hex()
    print("final" + final)
    if final == hash:
        return True
    else:
        return False


def encrypt_aes(texto, clave):
    # Convertir el texto a bytes
    texto_bytes = texto.encode()

    # Crear un objeto AES con la clave proporcionada
    cipher = AES.new(clave, AES.MODE_EAX)

    # Cifrar el texto
    nonce = cipher.nonce
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)

    # Convertir el texto cifrado en bytes a una cadena de texto
    texto_cifrado_str = texto_cifrado.hex()

    # Devolver el texto cifrado y el nonce
    return texto_cifrado_str, nonce.hex()

# Función para ofuscar el DNI
def ofuscar_dni(dni):
    return '*' * (len(dni) - 4) + dni[-4:]

if __name__ == '__main__':
    texto = "Hola Mundo"
    clave = get_random_bytes(16)
    texto_cifrado, nonce = encrypt_aes(texto, clave)
    print("Texto cifrado: " + texto_cifrado)
    print("Nonce: " + nonce)
    des = decrypt_aes(texto_cifrado, nonce, clave)
    print("Texto descifrado: " + des)
    password = "password"
    pwd_hash = hash_with_salt(password)
    print("Hash: " + pwd_hash[0])
    password_other = "password"
    print("Hash: " + hash_with_salt(password_other)[0])