# generate_encryption_key.py

from cryptography.fernet import Fernet

# Function to generate and save a new encryption key
def generate_key():
    # Generate a new encryption key
    encryption_key = Fernet.generate_key()

    # Define the path where you want to save the key
    key_path = 'db_operations/encryption.key'

    # Save the encryption key to a file
    with open(key_path, 'wb') as key_file:
        key_file.write(encryption_key)

    print(f"Encryption key saved at {key_path}")
