from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json

# Uncomment and run this function the first time to create a key file.
# def create_key():
#     key = Fernet.generate_key()
#     with open("key.key", "wb") as key_file:
#         key_file.write(key)
# create_key()

def load_key():
    try:
        with open("key.key", 'rb') as file:
            key = file.read()
            return key
    except FileNotFoundError:
        print("Key file not found. Please run create_key() function first.")
        exit()

def derive_key(master_pwd, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))

def encrypt_password(master_pwd, password):
    salt = os.urandom(16)
    derived_key = derive_key(master_pwd, salt)
    fernet = Fernet(derived_key)
    encrypted_password = fernet.encrypt(password.encode())
    return salt, encrypted_password

def decrypt_password(master_pwd, salt, encrypted_password):
    derived_key = derive_key(master_pwd, salt)
    fernet = Fernet(derived_key)
    return fernet.decrypt(encrypted_password).decode()

Master_pwd = input("Master Password: ")

def view():
    try:
        with open("passwords.txt", 'r') as f:
            for line in f.readlines():
                try:
                    data = json.loads(line.rstrip())
                    user = data['account']
                    salt = base64.b64decode(data['salt'])
                    encrypted_password = base64.b64decode(data['password'])
                    password = decrypt_password(Master_pwd, salt, encrypted_password)
                    print(f"User: {user}\tPassword: {password}")
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    print("Skipping malformed or corrupt line:", line)
    except FileNotFoundError:
        print("No passwords stored yet.")
    except Exception as e:
        print("An error occurred while reading passwords:", e)

def add():
    account = input("Account Name: ")
    password = input("Password: ")

    salt, encrypted_password = encrypt_password(Master_pwd, password)
    data = {
        'account': account,
        'salt': base64.b64encode(salt).decode('utf-8'),
        'password': base64.b64encode(encrypted_password).decode('utf-8')
    }

    with open("passwords.txt", 'a') as f:
        f.write(json.dumps(data) + "\n")

while True:
    mode = input("Enter ADD to add new password or VIEW to view existing ones (Press Q to quit): ").upper()
    if mode == "Q":
        break
    elif mode == "ADD":
        add()
    elif mode == "VIEW":
        view()
    else:
        print("Invalid Mode")
