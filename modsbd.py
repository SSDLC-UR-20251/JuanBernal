import json
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import os

# 🔑 Clave fija para cifrado AES
def fixed_key():
    key_str = "secDevCycle2025_1"
    hash_obj = SHA256.new(key_str.encode())
    return hash_obj.digest()[:16]

# 🔒 Cifrar DNI
def encrypt_dni(dni):
    KEY = fixed_key()
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(dni.encode())
    return base64.b64encode(ciphertext).decode(), base64.b64encode(cipher.nonce).decode()

# 🔑 Hash de contraseña con salt
def hash_with_salt(password):
    salt = get_random_bytes(16)
    password_bytes = salt + password.encode()
    hash_obj = SHA256.new()
    hash_obj.update(password_bytes)
    return hash_obj.hexdigest(), salt.hex()

# 📌 Función para actualizar la BD al formato correcto
def actualizar_bd(filename):
    # 📂 Cargar la base de datos
    with open(filename, 'r', encoding='utf-8') as file:
        db = json.load(file)

    # 🔄 Iterar sobre cada usuario
    for email, data in db.items():
        # 📌 Cifrar DNI si aún no está cifrado
        if "dni_nonce" not in data:
            dni_cifrado, dni_nonce = encrypt_dni(data["dni"])
            data["dni"] = dni_cifrado
            data["dni_nonce"] = dni_nonce

        # 🔐 Si la contraseña está en texto plano, convertirla en hash con salt
        if "password_hash" not in data:
            hashed_password, salt = hash_with_salt(data["password"])
            data["password_hash"] = hashed_password
            data["salt"] = salt
            del data["password"]  # Eliminar la contraseña en texto plano

        # 🏷️ Asegurar que tenga un rol por defecto si no existe
        if "role" not in data:
            data["role"] = "user"

    # 💾 Guardar los datos actualizados
    with open(filename, 'w', encoding='utf-8') as file:
        json.dump(db, file, indent=4)

    print(f"✅ Base de datos actualizada en {filename}")

# 📌 Ejecutar el script
if __name__ == "__main__":
    actualizar_bd("db.txt")
