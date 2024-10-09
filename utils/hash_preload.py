import os
import sys
from utils import utils_func
from db_operations import db_insert_records, db_get_records

# Directory containing the hash files to process
input_dir = "input\\Preload-Hashes"

# Hardcoded list of files to be processed
files_to_process = [
    "2019-Hash-Data.txt",
    "2020-Hash-Data.txt",
    "2021-Hash-Data.txt",
    "2022-Hash-Data.txt"
]

# Function to check the row count of the hash_data_ioc table
def check_hash_table():
    row_count = db_get_records.get_table_row_count("hash_data_ioc")
    if row_count is not None:
        if row_count > 0:
            print(f"Hash table has {row_count} row(s).")
        else:
            print(f"Hash table is currently empty.")
    else:
        print("[ERROR] Failed to retrieve row count for 'hash_data_ioc' table.")

# Function to process a single file
def process_file(file_path, file_name):
    print(f"Reading file: {file_name}...")

    # Read the hashes from the file
    hashes = utils_func.read_hash_file_data(file_path)

    # If no hashes were found or an error occurred, skip the file
    if not hashes:
        print(f"[ERROR] No valid hashes found in {file_name}. Skipping...")
        return

    print(f"Processing {len(hashes)} hash(es) from {file_name}...\n")

    # Process each hash in the file
    for hash_str in hashes:
        md5, sha1, sha256 = utils_func.determine_hash_fields(hash_str)

        # Convert the hashes to lowercase
        md5 = md5.lower() if md5 else None
        sha1 = sha1.lower() if sha1 else None
        sha256 = sha256.lower() if sha256 else None

        # Validate that at least one hash type is found
        if md5 or sha1 or sha256:
            # Check if the hash already exists in the database
            if not db_get_records.check_hash_exists(md5, sha1, sha256):
                db_insert_records.insert_hash_data(md5, sha1, sha256)

            else:
                print(f"Hash already exists in the database. Skipping insert.")
        else:
            print(f"[ERROR] Invalid hash format: {hash_str}. Skipping...")

    print(f"Finished processing {file_name}.\n")

# Main function to process all hash files
def process_hash_files():
    # Check if input directory exists, and exit if it does not
    if not os.path.exists(input_dir):
        print(f"[ERROR] Input directory does not exist: {input_dir}")
        sys.exit(1)

    # Check row count before processing files
    check_hash_table()

    print(f"Starting the hash processing from files in {input_dir}...\n")

    for file_name in files_to_process:
        file_path = os.path.join(input_dir, file_name)

        # Check if the file exists before processing
        if not os.path.exists(file_path):
            print(f"[ERROR] File not found: {file_name}. Skipping...")
            continue

        process_file(file_path, file_name)

    # Check row count again after processing files
    check_hash_table()

    print("All files have been processed.\n")

# Function to retrieve all hash data and put it into a list of strings
def get_all_hashes_list():
    print("\nFetching all records from hash IOC table.")

    records = db_get_records.get_all_hash_data()
    hash_list = []

    # Process each record and extract hashes (MD5, SHA1, SHA256)
    if records:
        for index in records:
            # Assuming the record is structured as a tuple
            if index[3]:  # SHA256
                hash_list.append(index[3])
            
            elif index[2]:  # SHA1
                hash_list.append(index[2])
            
            elif index[1]:  # MD5
                hash_list.append(index[1])

        print(f"Successfully retrieved {len(hash_list)} hash(es).")

    return hash_list
