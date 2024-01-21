# app_utils.py

import os
import time
import logging

# Constants
LOG_FILE = 'logs/utils.log'
ANALYSIS_RESULTS_DIR = 'output'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def read_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.readlines()
    except FileNotFoundError:
        logging.error(f"Error: File not found - {file_path}")
    except Exception as e:
        logging.error(f"Error reading file: {e}")
    return None

def android_apk_selection():
    apk_files = display_apk_files()
    if not apk_files: return
    apk_choice = get_user_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files)+1)])
    return apk_files[int(apk_choice) - 1]

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

def prompt_user_enter_apk_path():
    while True:
        user_data = input("Enter the path to the APK file: ").strip()
        if user_data and os.path.exists(user_data) and os.path.isfile(user_data):
            return user_data
        else:
            print("Invalid path or file.")

def prompt_user_enter_hash_ioc():
    while True:
        user_data = input("Enter the hash IOC: ").strip()
        if user_data:
            # Check if the hash is valid hexadecimal and determine its type
            if all(c in '0123456789abcdefABCDEF' for c in user_data):
                if len(user_data) == 32:
                    return user_data
                elif len(user_data) == 40:
                    return user_data
                elif len(user_data) == 64:
                    return user_data
                else:
                    print("Invalid hash length. Please enter a valid MD5, SHA1, or SHA256 hash.")
            else:
                print("Invalid hash. Hashes should contain hexadecimal characters only.")
        else:
            print("Please enter a valid hash.")

# Get and validate user choice
def get_user_choice(prompt, valid_choices):
    while True:
        try:
            choice = input(prompt).strip()
            if choice in valid_choices:
                return choice
            print("Invalid choice. Please select a valid option.")
        except KeyboardInterrupt:
            print()
            exit(0)

# Lists and displays all .apk files in the current directory
def display_apk_files():
    apk_files = [f for f in os.listdir() if f.endswith('.apk')]
    print("\nAvailable APK Files:" if apk_files else "No APK files found.")
    for i, file in enumerate(apk_files, 1):
        print(f" [{i}] {file}")
    return apk_files

def wait_for_next_batch(batch_interval):
    try:      
        # Calculate time left for the next batch after the first iteration
        time_left = batch_interval
        for j in range(3, 0, -1):
            minutes_left = time_left // 60          
            if minutes_left == 4:
                print(f"{minutes_left} minutes left.")
            elif minutes_left > 1:
                print(f"{minutes_left} minutes left.")
            elif minutes_left == 1:
                print(f"{minutes_left} minute seconds left.")
            
            time_left -= 60
            time.sleep(60)

    except KeyboardInterrupt:
        print("\nExiting.")
        exit()