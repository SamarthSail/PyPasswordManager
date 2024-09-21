# Password Manager
This is a simple and secure password manager written in Python. It allows you to securely store account credentials (username/password) in an encrypted file, protected by a master password. It utilizes PBKDF2-HMAC for key derivation, SHA-256 for password hashing, and Fernet encryption from the cryptography library to encrypt and decrypt passwords.

Features
Master Password: Protects access to the stored passwords.
Encryption: Passwords are encrypted using Fernet symmetric encryption.
Salted Hashing: The master password is hashed with a salt using SHA-256 to prevent rainbow table attacks.
PBKDF2HMAC: Ensures that the encryption key derived from the master password is secure.
Password Storage: Account names and encrypted passwords are stored in a text file (passwords.txt).

Prerequisites
Python 3.x must be installed on your machine. 
You will need the cryptography library. Install it using the following command:
- pip install cryptography

Installation
Option 1: Clone the Repository
1. Clone the repository:
- git clone https://github.com/yourusername/your-repo.git
- cd your-repo
2. Install the required Python library:
- pip install cryptography
3. Run the program:
- python PassManager.py

Option 2: Download and Run the Python Script
1. Download the PassManager.py file from this repository.
2. Install the required Python library:
- pip install cryptography
3. Run the program:
- python PassManager.py

# Usage
1. First Run - Set Master Password
When you run the script for the first time, it will prompt you to create a master password.
This password will be used to encrypt and decrypt the stored credentials.

2. Adding a Password
Once the master password is verified, the program will ask whether you want to add a new password or view existing ones.
To add a new password, type add when prompted.
The account name and password will be stored securely in the passwords.txt file, with the password encrypted.

3. Viewing Passwords
To view your stored passwords, type view when prompted. You will see the account names along with their decrypted passwords.

4. Exiting
You can exit the program by typing q when prompted.

# Security Features
Master Password Protection: The user is required to set and enter a master password to access stored credentials. This password is hashed and stored securely.
Salted Password Hashing: The master password is combined with a randomly generated salt and hashed using SHA-256 before storing it in master_password.txt.
Key Derivation Function: The encryption key is derived using the PBKDF2HMAC function with 100,000 iterations, ensuring strong security.
Fernet Encryption: Uses the derived key to encrypt and decrypt passwords stored in passwords.txt.
Encrypted Storage: Passwords are stored in the passwords.txt file in an encrypted format, making them unreadable without the correct master password.

# Future Improvements 
Add multi-user support with separate password databases for each user.
Add deletion feature for passwords by choosing a password based on account name.
Add a seperator for an account username for each website accordingly.
Add an option to choose an auto-generated strong password for an account
Consider different options to secure key, salt and masterpassword files to avoid being easily discovered in the local directories
