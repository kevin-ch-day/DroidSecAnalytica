# app_utils.py

import os
import zipfile
import logging
import calendar

from . import logging_utils

# Constants
LOG_FILE = 'logs/utils.log'
ANALYSIS_RESULTS_DIR = 'output'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def utility_functions_menu():
    print(format_menu_title("Utility Functions Menu"))
    print(format_menu_option(1, "API Integration Check"))
    print(format_menu_option(2, "View Logs"))
    print(format_menu_option(0, "Back to Main Menu"))

def handle_utilities():
    utility_functions_menu()
    utility_choice = get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])
    if utility_choice == '0':
        return
    
    elif utility_choice == '1':
        print("API Integration Check.")

    elif utility_choice == '2':
        print("View logs.")
        logging_utils.handle_view_logs()

def android_apk_selection():
    apk_files = display_apk_files()
    if not apk_files: return
    apk_choice = get_user_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files)+1)])
    return apk_files[int(apk_choice) - 1]

def determine_hash_fields(hash_str):
    # Handle None or empty string input
    if not hash_str:
        print('No hash string provided. The input is empty or None.')
        return None, None, None

    # Validate hash string for hexadecimal characters
    if not all(c in '0123456789abcdefABCDEF' for c in hash_str):
        print(f'Invalid hash string: "{hash_str}". Hash must be hexadecimal.')
        return None, None, None

    # Determine the type of hash based on its length
    md5, sha1, sha256 = None, None, None
    if len(hash_str) == 32:
        md5 = hash_str
    elif len(hash_str) == 40:
        sha1 = hash_str
    elif len(hash_str) == 64:
        sha256 = hash_str
    else:
        print(f'Invalid hash string length: "{hash_str}". Unrecognized hash type.')
        return None, None, None

    return md5, sha1, sha256

def write_data_to_file(data_filename, headers_line, max_lengths, rows):
    try:
        with open(data_filename, 'w') as data_file:
            data_file.write(headers_line + '\n')
            data_file.write('-' * len(headers_line) + '\n')
            for row in rows:
                formatted_row = ' | '.join([str(row[i]).ljust(max_lengths[i]) for i in range(len(row))])
                data_file.write(formatted_row + '\n')

    except IOError as error:  # More descriptive error messages
        print(f'IOError occurred: {error}. Check file permissions and path.')
        print(f"Error writing data to file: {error}")

def parse_file(file_path):
    print('Parsing file:', file_path)

    # Generate a mapping from abbreviated to full month names
    month_mapping = {month: calendar.month_name[i] for i, month in enumerate(calendar.month_abbr) if month}

    # Remove 'input/' from the file_path
    simplified_file_path = file_path.replace('input/', '')

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
    except IOError as error:
        print(f'IOError occurred: {error}. Check file permissions and path.')
        return []

    malware_data = []
    current_month = None
    current_category = None

    for line_number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue  # Skip empty lines

        if line.startswith('**'):
            month_str = line.strip('*').strip()
            # Convert abbreviated month name to full name if necessary
            current_month = month_mapping.get(month_str, month_str)
        elif line.startswith('-'):
            current_category = line.strip('-').strip()
        elif current_category:
            hash_str = line
            try:
                md5, sha1, sha256 = determine_hash_fields(hash_str)
                if not any([md5, sha1, sha256]):
                    raise ValueError(f"Invalid hash string: '{hash_str}'")

                malware_data.append((current_category, md5, sha1, sha256, simplified_file_path, current_month))
            except ValueError as e:
                print(f"Error at line {line_number} in file {file_path}: {e}")
                print(f"Problematic data: '{line}'")

    return malware_data

def write_top_hashes(title, analysis_file, cursor, hash_type):
    # Improved output format for better readability
    analysis_file.write(f'{title} - Top 10 {hash_type.upper()} Hashes:\n')
    analysis_file.write(f"\n{title}:\n")
    sql = f"SELECT {hash_type}, COUNT(*) FROM android_malware_hashes WHERE {hash_type} IS NOT NULL GROUP BY {hash_type} ORDER BY COUNT(*) DESC LIMIT 10"
    cursor.execute(sql)
    top_hashes = cursor.fetchall()
    for hash_value, count in top_hashes:
        analysis_file.write(f"  - {hash_type.upper()} Hash: {hash_value}, Count: {count}\n")

def find_similar_categories(target_category, category_counts):
    similar_categories = []
    for category, _ in category_counts:
        if target_category != category:
            # Check if the target_category is a substring of category or vice versa
            if target_category in category or category in target_category:
                similar_categories.append(category)
    return similar_categories

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