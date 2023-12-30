import logging
import json
import os
import time
import pandas as pd
from functools import wraps
from cryptography.fernet import Fernet
import os
import joblib
import zipfile
import subprocess
from xml.etree import ElementTree as ET

# Constants
LOG_FILE = 'logs/utils.log'
ANALYSIS_RESULTS_DIR = 'analysis_results'
DEX2JAR_TOOL = 'd2j-dex2jar'
APK_TOOL = 'apktool'

# Define the path to the directory containing your machine learning models
MODEL_DIR = "models"

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def create_output_directory():
    """
    Create the directory for analysis results if it doesn't exist.
    """
    try:
        os.makedirs(ANALYSIS_RESULTS_DIR, exist_ok=True)
    except OSError as e:
        print(f"Error creating directory: {e}")

def save_results(apk_path, manifest_data):
    """
    Save the analysis results to a file.

    Args:
        apk_path (str): The path to the APK file.
        manifest_data (dict): The analyzed data to be saved.
    """
    try:
        create_output_directory()
        output_file = os.path.join(ANALYSIS_RESULTS_DIR, f"{os.path.splitext(os.path.basename(apk_path))[0]}_analysis_results.txt")
        
        with open(output_file, "w") as f:
            f.write("Analysis Results:\n")
            f.write(f"APK Name: {os.path.basename(apk_path)}\n")
            
            # Write additional analysis data here
            
        print(f"Analysis results saved to {output_file}")

    except Exception as e:
        print(f"Error saving analysis results: {e}")

def copy_android_manifest(apk_path):
    """
    Copy AndroidManifest.xml content to a text file.

    Args:
        apk_path (str): The APK file path.
    """
    output_path = os.path.join(ANALYSIS_RESULTS_DIR, 'AndroidManifest.txt')

    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            with apk_zip.open('AndroidManifest.xml') as manifest_file:
                manifest_content = manifest_file.read().decode('utf-8')

        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(manifest_content)

        print(f"AndroidManifest.xml successfully copied to {output_path}")

    except FileNotFoundError as e:
        logging.error(f"Error: {e}.")

    except Exception as e:
        logging.error(f"Error copying AndroidManifest.xml: {e}")

def decompile_apk(apk_path):
    """
    Decompile an APK file.

    Args:
        apk_path (str): The path to the APK file.
    """
    try:
        output_directory = os.path.splitext(apk_path)[0]
        subprocess.run([APK_TOOL, "d", apk_path, "-o", output_directory], check=True)
        print(f"APK decompiled successfully. Output directory: {output_directory}")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error decompiling APK: {e}")

def generate_jar(apk_path):
    """
    Generate a JAR file from an APK file.

    Args:
        apk_path (str): The path to the APK file.

    Returns:
        str: The path to the generated JAR file, or None if an error occurred.
    """
    try:
        output_dir = os.path.splitext(apk_path)[0]
        jar_path = f"{output_dir}-dex2jar.jar"

        subprocess.run([DEX2JAR_TOOL, apk_path, "-o", jar_path], check=True)

        print(f"Successfully generated JAR file: {jar_path}")
        return jar_path

    except subprocess.CalledProcessError as e:
        logging.error(f"Error generating JAR file: {e}")
        return None
    
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return None

def analyze_jar(apk_path):
    """
    Analyze a JAR file and return a list of classes found.

    Args:
        apk_path (str): The path to the APK file.

    Returns:
        list: A list of class file names found in the JAR.
    """
    jar_path = f"{apk_path[:-4]}-dex2jar.jar"
    classes_found = []

    try:
        with zipfile.ZipFile(jar_path, 'r') as zipped_file:
            classes_found = [zipped_file_info.filename for zipped_file_info in zipped_file.infolist() if zipped_file_info.filename.endswith('.class')]

        return classes_found

    except zipfile.BadZipfile as e:
        logging.error(f"Error analyzing JAR file {jar_path}: {e}")
        return []
    
    except Exception as e:
        logging.error(f"Unexpected error analyzing JAR file {jar_path}: {e}")
        return []

# Define the path to the directory containing your machine learning models
MODEL_DIR = "models"

def change_model():
    """
    Implementation of changing the machine learning model.
    """
    print("Changing the machine learning model...")

    # List available models in the 'models' directory
    available_models = os.listdir(MODEL_DIR)

    if not available_models:
        print("No machine learning models found.")
        return

    # Display available models to the user
    print("Available models:")
    for idx, model_name in enumerate(available_models, start=1):
        print(f"{idx}. {model_name}")

    # Prompt the user to select a model
    try:
        model_idx = int(input("Enter the number of the model to use: ")) - 1
        selected_model = available_models[model_idx]

        # Load the selected model
        model_path = os.path.join(MODEL_DIR, selected_model)
        model = joblib.load(model_path)

        # Now you can use the 'model' for APK analysis

        print(f"Using model: {selected_model}")
    except (ValueError, IndexError):
        print("Invalid model selection. Please enter a valid number.")

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