import os
import base64
import hashlib
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Derive a key from the master password using PBKDF2HMAC
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Hash the master password for secure storage (using SHA256)
def hash_password(password, salt):
    return hashlib.sha256(password.encode() + salt).hexdigest()

# Get or create the salt for password hashing
def get_or_create_salt():
    if not os.path.exists("salt.salt"):
        salt = os.urandom(16)  # Generate a new salt
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
        return salt
    else:
        with open("salt.salt", "rb") as salt_file:
            return salt_file.read()

# Set up the master password on the first run
def setup_master_password():
    master_password = getpass.getpass("Set your master password: ")
    salt = get_or_create_salt()  # Create and store a salt
    hashed_password = hash_password(master_password, salt)  # Hash the master password

    # Save the hashed password to file
    with open("master_password.txt", "w") as f:
        f.write(hashed_password)
    
    print("Master password setup complete.")

# Verify the master password on subsequent runs
def verify_master_password():
    # Load the stored hashed password and salt
    salt = get_or_create_salt()
    try:
        with open("master_password.txt", "r") as f:
            stored_hashed_password = f.read().strip()

        # Ask the user to enter the master password
        entered_password = getpass.getpass("Enter your master password: ")
        entered_hashed_password = hash_password(entered_password, salt)

        # Compare entered hashed password with the stored hash
        if entered_hashed_password == stored_hashed_password:
            print("Master password verified.")
            return entered_password  # Return the master password
        else:
            print("Incorrect master password.")
            return None
    except FileNotFoundError:
        print("No master password is set. Please run the setup.")
        return None

# Function to derive the encryption key from the master password
def get_fernet_instance(master_password):
    salt = get_or_create_salt()  # Load or create a salt
    key = derive_key_from_password(master_password, salt)  # Derive the key
    return Fernet(key)

# Function to view stored account names and decrypted passwords
def view(fer):
    try:
        with open('passwords.txt', 'r') as f:
            for line in f.readlines():
                try:
                    data = line.rstrip()
                    if "|" not in data:  # Check if the line contains the separator
                        print(f"Skipping invalid line: {data}")
                        continue
                    
                    user, passw = data.split("|", 1)  # Safely split the data
                    # Decrypt and display the password
                    decrypted_password = fer.decrypt(passw.encode()).decode()
                    print(f"User: {user} | Password: {decrypted_password}")
                except Exception as e:
                    print(f"Error decrypting password for this entry: {e}")
    except FileNotFoundError:
        print("No passwords stored yet.")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")


# Function to add a new account and encrypted password
def add(fer):
    name = input('Account Name: ')
    pwd = input("Password: ")

    with open('passwords.txt', 'a') as f:
        # Encrypt the password and save it in the format "Account|EncryptedPassword"
        f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")

# Main logic to run the password manager
if not os.path.exists("master_password.txt"):
    print("No master password found. You need to set up a master password.")
    setup_master_password()

master_password = verify_master_password()  # Get the master password once
if master_password:  # If verification is successful
    fer = get_fernet_instance(master_password)  # Create Fernet instance using the master password

    while True:
        mode = input("Would you like to add a new password or view existing ones (view, add), press q to quit? ").lower()
        if mode == "q":
            break

        if mode == "view":
            view(fer)
        elif mode == "add":
            add(fer)
        else:
            print("Invalid mode.")
else:
    print("Exiting program due to failed master password verification.")
