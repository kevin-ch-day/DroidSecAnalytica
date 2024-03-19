import mysql.connector
import getpass
from utils import logging_utils  # Import logging_utils

# Configure logging using logging_utils
logging_utils.configure_logging(filename='logs/config_setup.log', level=logging_utils.INFO)

# Function to get user input for database configuration
def get_user_input():
    logging_utils.log_info("Enter the MySQL database configuration:")
    db_host = input("Database Host: ")
    db_user = input("Database User: ")
    db_password = getpass.getpass("Database Password: ")
    db_database = input("Database Name: ")
    return db_host, db_user, db_password, db_database

# Function to compare user input with existing config
def compare_config(user_config):
    try:
        from database import db_config  # Import the existing configuration
        existing_config = (db_config.DB_HOST, db_config.DB_USER, db_config.DB_PASSWORD, db_config.DB_DATABASE)
        return user_config == existing_config

    except ImportError:
        return False  # If the import fails, the config doesn't exist yet

# Function to test the database connection with retries
def test_database_connection(user_config):
    db_host, db_user, db_password, db_database = user_config
    connection_attempts = 0

    logging_utils.log_info("Testing database connection...")
    while connection_attempts < 3:
        try:
            conn = mysql.connector.connect(
                host=db_host,
                user=db_user,
                password=db_password,
                database=db_database
            )
            conn.close()
            logging_utils.log_info("Connection successful.")
            return True
        except mysql.connector.Error as err:
            logging_utils.log_error(f"Connection failed: {err}")
            connection_attempts += 1
    
    logging_utils.log_error("Failed to connect to the database three times. Exiting.")
    return False

# Function to update config
def update_config(user_config):
    with open("database/db_config.py", "w") as config_file:
        config_file.write(f'# db_config.py\n\n')
        config_file.write(f'DB_HOST = "{user_config[0]}"\n')
        config_file.write(f'DB_USER = "{user_config[1]}"\n')
        # Encrypt and store the password securely (implement encryption logic here)
        config_file.write(f'DB_PASSWORD = "{encrypt_password(user_config[2])}"\n')
        config_file.write(f'DB_DATABASE = "{user_config[3]}"\n')

# Function to encrypt the database password (implement encryption logic)
def encrypt_password(password):
    # Implement encryption logic here
    return password

def main():
    logging_utils.log_info("Database Configuration Setup")
    logging_utils.log_info("-----------------------------")
    
    user_config = get_user_input()

    if compare_config(user_config):
        logging_utils.log_info("\nDatabase configuration is identical to the existing configuration.")
    else:
        logging_utils.log_info("\nNew database configuration detected:")
        logging_utils.log_info(f"Host: {user_config[0]}")
        logging_utils.log_info(f"User: {user_config[1]}")
        logging_utils.log_info("Password: *****")  # Mask the password
        logging_utils.log_info(f"Database: {user_config[3]}")

        if test_database_connection(user_config):
            confirmation = input("\nDo you want to overwrite the existing database configuration? (yes/no): ")
            
            if confirmation.lower() == "yes":
                update_config(user_config)
                logging_utils.log_info("Database configuration updated successfully.")
            else:
                logging_utils.log_info("Database configuration remains unchanged.")
        else:
            logging_utils.log_error("Exiting due to database connection failure.")

if __name__ == "__main__":
    main()
