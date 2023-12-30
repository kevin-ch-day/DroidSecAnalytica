import logging
import json
import os
import time
import pandas as pd
from functools import wraps
from cryptography.fernet import Fernet

# Logger setup
def setup_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

# Save data to Excel
def save_to_excel(data, file_path):
    print(f"Saving data to {file_path}...")
    if isinstance(data, dict):
        data = pd.DataFrame.from_dict(data)
    if not isinstance(data, pd.DataFrame):
        print("Data is not a DataFrame or dictionary.")
        return

    try:
        data.to_excel(file_path, index=False)
        print(f"Data successfully saved to {file_path}")
    except Exception as e:
        print(f"Error saving data to Excel: {e}")

def load_from_json(file_path):
    """
    Loads data from a JSON file.

    :param file_path: Path to the JSON file.
    :return: Loaded data.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

# Load configuration settings from JSON
def load_config(config_path):
    return load_from_json(config_path)

# Ensure directory exists
def ensure_directory_exists(directory_path):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"Created directory: {directory_path}")

# Convert dictionary to DataFrame
def convert_dict_to_dataframe(dict_data):
    return pd.DataFrame.from_dict(dict_data)

# Exception handler decorator
def exception_handler(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Error in {func.__name__}: {e}")
            return None
    return wrapper

# Measure performance decorator
def measure_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"{func.__name__} completed in {end_time - start_time} seconds")
        return result
    return wrapper

# Generate encryption key
def generate_encryption_key():
    print("Generating a new encryption key...")
    return Fernet.generate_key()

# Encrypt data
def encrypt_data(data, key):
    print("Encrypting data...")
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data
def decrypt_data(encrypted_data, key):
    print("Decrypting data...")
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

# Save encrypted JSON
def save_encrypted_json(data, file_path, key):
    print(f"Saving encrypted data to {file_path}...")
    encrypted_data = encrypt_data(json.dumps(data), key)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)
    print("Data encrypted and saved successfully.")

# Load encrypted JSON
def load_encrypted_json(file_path, key):
    print(f"Loading encrypted data from {file_path}...")
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = decrypt_data(encrypted_data, key)
    print("Data decrypted and loaded successfully.")
    return json.loads(decrypted_data)