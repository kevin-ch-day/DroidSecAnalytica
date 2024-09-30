# database_setup_manager.py

# Python Libraries
import mysql.connector
import getpass
import os
import shutil
from cryptography.fernet import Fernet

# Custom Libraries
from db_schema import db_setup
from security import generate_encryption_key

# Paths for config and encryption key
CONFIG_PATH = "db_operations/db_config.py"
KEY_PATH = "db_operations/encryption.key"

# Hardcoded database name
DB_NAME = "droidsecanalytica_dev"

# Function to load or generate encryption key
def load_or_generate_key():
    if os.path.exists(KEY_PATH):
        # Check if the file is empty or has invalid content
        if os.path.getsize(KEY_PATH) == 0:
            print(f"[INFO] Encryption key file at {KEY_PATH} is empty. Generating a new key.")
            generate_encryption_key.generate_key()
        else:
            # Load the encryption key from a file
            with open(KEY_PATH, 'rb') as key_file:
                key = key_file.read()
                try:
                    # Validate the key (Fernet requires a valid base64-encoded key)
                    Fernet(key)
                    print(f"[INFO] Encryption key loaded from {KEY_PATH}.")
                except ValueError:
                    print(f"[ERROR] Invalid encryption key found in {KEY_PATH}. Generating a new key.")
                    generate_encryption_key.generate_key()
    else:
        # If the file doesn't exist, create it and generate a new encryption key
        print(f"[INFO] No encryption key found at {KEY_PATH}. Generating a new key and creating the file.")
        generate_encryption_key.generate_key()

    with open(KEY_PATH, 'rb') as key_file:
        key = key_file.read()
    return key

# Load the encryption key
encryption_key = load_or_generate_key()
cipher_suite = Fernet(encryption_key)

# Function to get user input for database configuration
def get_user_input():
    print("\nPlease enter your MySQL database configuration:")
    
    db_host = input("Database Host: ").strip()
    db_user = input("Database User: ").strip()
    db_password = getpass.getpass("Database Password (Leave blank for no password): ").strip()

    # Validate input: ensure all fields are filled in except password, which is optional
    if not db_host or not db_user:
        print("\n[ERROR] Host and User fields are required. Please try again.")
        return get_user_input()  # Recursively prompt until valid input is provided

    # If no password is provided, display a warning
    if not db_password:
        print("\n[WARNING] No password provided. This might be a security risk!")

    return db_host, db_user, db_password

# Function to compare user input with existing config
def compare_config(user_config):
    try:
        from db_operations import db_config  # Import the existing configuration
        existing_config = (
            db_config.DB_HOST, 
            db_config.DB_USER, 
            db_config.DB_PASSWORD, 
            db_config.DB_DATABASE
        )
        return user_config == existing_config
    except ImportError:
        return False  # If the import fails, the config doesn't exist yet

# Function to test or create the database if it doesn't exist
def test_or_create_database(user_config):
    db_host, db_user, db_password = user_config
    connection_attempts = 0

    print("\n[INFO] Testing database connection...")
    while connection_attempts < 3:
        try:
            conn = mysql.connector.connect(
                host=db_host,
                user=db_user,
                password=db_password
            )
            cursor = conn.cursor()
            
            # Check if the database exists
            cursor.execute(f"SHOW DATABASES LIKE '{DB_NAME}';")
            result = cursor.fetchone()
            
            # If the database doesn't exist, create it
            if not result:
                print(f"[INFO] Database '{DB_NAME}' does not exist. Creating it now...")
                cursor.execute(f"CREATE DATABASE {DB_NAME};")
                print(f"[SUCCESS] Database '{DB_NAME}' created successfully.")
                cursor.close()
                conn.close()
                
                # Load and set up the schema using db_setup.py
                print("\n[INFO] Loading the database schema and tables.")
                try:
                    db_setup.setup_database(user_config)
                    print("[SUCCESS] Database schema and tables were successfully loaded.")
                except Exception as e:
                    print(f"[ERROR] Failed to load database schema using db_setup.py: {e}")
            
            else:
                print(f"[INFO] Connected to database '{DB_NAME}'.")
                conn.close()
            return True
        except mysql.connector.Error as err:
            print(f"[ERROR] Connection failed: {err}")
            connection_attempts += 1
    
    print("\n[ERROR] Failed to connect to the database three times. Exiting.")
    return False

# Function to encrypt the database password using Fernet encryption
def encrypt_password(password):
    encrypted_password = cipher_suite.encrypt(password.encode('utf-8'))
    return encrypted_password.decode('utf-8')

# Function to create a backup of the existing config
def backup_existing_config():
    if os.path.exists(CONFIG_PATH):
        backup_path = CONFIG_PATH + ".backup"
        shutil.copy(CONFIG_PATH, backup_path)
        print(f"[INFO] Existing configuration backed up at {backup_path}.")

# Function to update config
def update_config(user_config):
    backup_existing_config()  # Create a backup of the current config
    
    with open(CONFIG_PATH, "w") as config_file:
        config_file.write(f'# db_config.py\n\n')
        config_file.write(f'DB_HOST = "{user_config[0]}"\n')
        config_file.write(f'DB_USER = "{user_config[1]}"\n')
        
        # Encrypt and store the password securely
        encrypted_password = encrypt_password(user_config[2])
        config_file.write(f'DB_PASSWORD = "{encrypted_password}"\n')
        config_file.write(f'DB_DATABASE = "{DB_NAME}"\n')

    print(f"[INFO] Database configuration saved to {CONFIG_PATH}.")

# Main function to run the config setup process
def main():
    print("\n===============================================")
    print("   Welcome to the Database Configuration Setup")
    print("===============================================\n")
    
    user_config = get_user_input()
    
    if compare_config(user_config):
        print("\n[INFO] Database configuration is identical to the existing configuration.")
    else:
        print("\n[INFO] New database configuration detected:\n")
        print(f"Host: {user_config[0]}")
        print(f"User: {user_config[1]}")
        print(f"Password: *****")  # Mask the password
        print(f"Database: {DB_NAME}")

        if test_or_create_database(user_config):
            confirmation = input("\nDo you want to overwrite the existing database configuration? (yes/no): ")
            
            if confirmation.lower() == "yes":
                update_config(user_config)
                print("\n[INFO] Database configuration updated successfully.")
            else:
                print("\n[INFO] Database configuration remains unchanged.")
        else:
            print("\n[ERROR] Exiting due to database connection failure.")

if __name__ == "__main__":
    main()
