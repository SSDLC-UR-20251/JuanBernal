from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time
import re
import datetime
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

driver = webdriver.Chrome()
driver.get("http://localhost:5000/login")

# Iniciar sesión
driver.find_element(By.ID, "email").send_keys("juanseba.bernal@urosario.edu.co")
driver.find_element(By.ID, "password").send_keys("1723JAJa*")
driver.find_element(By.ID, "login").click()

time.sleep(2)

#deposito
saldo_texto = driver.find_element(By.ID, "saldo_usuario").text
saldo_inicial = float(saldo_texto.split(":")[-1].strip())

print(f"Saldo inicial: {saldo_inicial}")

driver.find_element(By.ID, "deposit_button").click()
time.sleep(2)
driver.find_element(By.ID, "balance").send_keys("100")
driver.find_element(By.ID, "deposit_button").click()
time.sleep(2)

saldo_texto = driver.find_element(By.ID, "saldo_usuario").text
saldo_final = float(saldo_texto.split(":")[-1].strip()) 
print(f"Saldo final: {saldo_final}")

#prueba triste
driver.find_element(By.ID, "withdraw_button").click()
time.sleep(2)
driver.find_element(By.ID, "balance").send_keys("50")
driver.find_element(By.ID, "password").send_keys("Rosendo")
driver.find_element(By.ID, "withdraw_button").click()
alarma = driver.find_element(By.ID, "alarma").text
if alarma == "Contraseña incorrecta":
    print("Prueba triste exitosa")
time.sleep(2)

#prueba feliz
driver.find_element(By.ID, "logout").click()
time.sleep(2)
#print(driver.find_element(By.ID, "register").get_attribute("href"))
driver.get("http://localhost:5000/register")
time.sleep(2)
driver.find_element(By.ID, "nombre").send_keys("Juan")
driver.find_element(By.ID, "Apellidos").send_keys("Bernal")
driver.find_element(By.ID, "username").send_keys("juanseba.bernal")
driver.find_element(By.ID, "email").send_keys("juanseba.bernal@gmail.com")
driver.find_element(By.ID, "password").send_keys("1723JAJa*")
driver.find_element(By.ID, "dni").send_keys("1234567890")
fecha = datetime.datetime(2004, 12, 23)
# Convertir la fecha al formato MM/DD/YYYY
fecha_str = fecha.strftime("%m/%d/%Y")  # '12/23/2004'
# Enviar la fecha al campo de entrada
driver.find_element(By.ID, "dob").send_keys(fecha_str)
driver.find_element(By.ID, "register_button").submit()
time.sleep(2)
alarma = driver.find_element(By.ID, "alarma").text
if alarma == "['Email inválido']":
    print("Prueba feliz exitosa")
time.sleep(2)