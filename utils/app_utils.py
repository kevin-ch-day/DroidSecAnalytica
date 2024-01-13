import os
import zipfile
import logging

# Constants
LOG_FILE = 'logs/utils.log'
ANALYSIS_RESULTS_DIR = 'output'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

# Helper function to format the menu title
def format_menu_title(title, width=30):
    return f"\n{title}\n" + "=" * width

# Helper function to format each menu option
def format_menu_option(number, description):
    return f" [{number}] {description}"

# Display the application name in a stylish header
def display_app_name(app_name="DroidSecAnalytica"):
    header_width = 40
    top_border = "╔" + "═" * (header_width - 2) + "╗"
    app_name_header = "║" + app_name.center(header_width - 2) + "║"
    bottom_border = "╚" + "═" * (header_width - 2) + "╝"
    print("\n" + top_border)
    print(app_name_header)
    print(bottom_border)

# Get and validate user choice
def get_user_choice(prompt, valid_choices):
    while True:
        choice = input(prompt).strip()
        if choice in valid_choices:
            return choice
        print("Invalid choice. Please select a valid option.")

# Lists and displays all .apk files in the current directory
def display_apk_files():
    apk_files = [f for f in os.listdir() if f.endswith('.apk')]
    print("\nAvailable APK Files:" if apk_files else "No APK files found.")
    for i, file in enumerate(apk_files, 1):
        print(f" [{i}] {file}")
    return apk_files

# Lists all log files in the specified directory
def list_log_files(log_directory):
    log_files = [f for f in os.listdir(log_directory) if f.endswith('.log')]
    if not log_files:
        print("No log files found.")
        return []
    for i, file in enumerate(log_files, 1):
        print(f" [{i}] {file}")
    return log_files

# Displays the content of a selected log file
def view_log_file(log_directory, log_files, choice):
    file_path = os.path.join(log_directory, log_files[choice - 1])
    with open(file_path, 'r') as file:
        print(file.read())

# Handles the process of viewing log files
def handle_view_logs():
    log_directory = 'output'
    log_files = list_log_files(log_directory)
    if log_files:
        try:
            choice = int(input("Enter the number of the log file to view: "))
            if 0 < choice <= len(log_files):
                view_log_file(log_directory, log_files, choice)
            else:
                print("Invalid selection.")
        except ValueError:
            print("Please enter a valid number.")

def copy_android_manifest(apk_path):
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