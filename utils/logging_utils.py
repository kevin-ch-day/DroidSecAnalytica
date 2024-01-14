import os
import logging

# Constants
LOG_FILE = 'logs/enhanced_utils.log'
ANALYSIS_RESULTS_DIR = 'output'

# Configure advanced logging
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s: %(message)s')

# Enhanced logging and error handling functions
def log_and_print(message, level="info"):
    if level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)
    else:
        logging.info(message)
    print(message)

def try_except_log(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log_and_print(f"Exception in {func.__name__}: {e}", "error")
    return wrapper

def list_log_files(log_directory):
    log_files = [f for f in os.listdir(log_directory) if f.endswith('.log')]
    if not log_files:
        log_and_print("No log files found.")
        return []
    for i, file in enumerate(log_files, 1):
        log_and_print(f" [{i}] {file}")
    return log_files

def view_log_file(log_directory, log_files, choice):
    file_path = os.path.join(log_directory, log_files[choice - 1])
    with open(file_path, 'r') as file:
        log_and_print(file.read())

def handle_view_logs():
    log_directory = 'output'
    log_files = list_log_files(log_directory)
    if log_files:
        try:
            choice = int(input("Enter the number of the log file to view: "))
            if 0 < choice <= len(log_files):
                view_log_file(log_directory, log_files, choice)
            else:
                log_and_print("Invalid selection.")
        except ValueError:
            log_and_print("Please enter a valid number.")