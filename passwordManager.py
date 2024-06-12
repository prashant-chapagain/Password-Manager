from cryptography.fernet import Fernet

# Uncomment and run this function the first time to create a key file.
# def create_key():
#     key = Fernet.generate_key()
#     with open("key.key", "wb") as key_file:
#         key_file.write(key)
# create_key()

def loadKey():
    try:
        with open("key.key", 'rb') as file:
            key = file.read()
            return key
    except FileNotFoundError:
        print("Key file not found. Please run create_key() function first.")
        exit()

Master_pwd = input("Master Password: ")

key = loadKey() + Master_pwd.encode()
fer = Fernet(key)

def view():
    try:
        with open("passwords.txt", 'r') as f:
            for line in f.readlines():
                data = line.rstrip()
                if "|" in data:
                    user, passw = data.split("|")
                    print("User:", user, "\tPassword:", fer.decrypt(passw.encode()).decode())
                else:
                    print("Skipping malformed line:", data)
    except FileNotFoundError:
        print("No passwords stored yet.")

def add():
    name = input("Account Name: ")
    password = input("Password: ")

    with open("passwords.txt", 'a') as f:
        f.write(name + "|" + fer.encrypt(password.encode()).decode() + "\n")

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
