# app_utils.py

import os
import zipfile
import logging

# Constants
LOG_FILE = 'logs/utils.log'
ANALYSIS_RESULTS_DIR = 'output'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

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