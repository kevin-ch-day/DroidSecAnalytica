import os
import pandas as pd
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

def get_unanalyzed_hashes():
    # Fetches all unanalyzed SHA256 hashes from the 'hash_data_ioc' table 
    # and returns them as a list of strings.

    # Display section title
    print("\n" + "=" * 80)
    print("FETCHING UNANALYZED SHA256 HASHES".center(80))
    print("=" * 80 + "\n")

    # Retrieve records from the database
    records = db_get_records.get_unanalyzed_database_hashes()

    # Extract SHA256 hashes into a list
    hash_list = [record["sha256"] for record in records] if records else []

    # Display results
    if hash_list:
        print(f"Retrieved {len(hash_list):,} unanalyzed hash(es).")
        print("These hashes have NOT yet been analyzed in the database.\n")
    else:
        print("No unanalyzed hashes found. All entries in 'hash_data_ioc' have been processed.\n")

    print("=" * 80 + "\n")
    return hash_list

def load_hashes_from_txt():
    """List and load hashes from a selected text (.txt) file in the input directory."""
    input_dir = "input"

    # List available .txt files
    txt_files = [f for f in os.listdir(input_dir) if f.endswith(".txt")]

    if not txt_files:
        print("\n[ERROR] No .txt files found in the 'input' directory.")
        return None

    print("\n" + "=" * 40)
    print("      Load Hashes from Text File")
    print("=" * 40)

    # Display available files
    options = {i + 1: os.path.join(input_dir, file) for i, file in enumerate(txt_files)}

    for num, file in options.items():
        print(f"  [{num}] {os.path.basename(file)}")

    # Get user selection
    while True:
        try:
            choice = int(input("\nEnter the number of the text file you want to load: "))
            if choice in options:
                file_path = options[choice]
                print(f"\nLoading hashes from {file_path}.")
                with open(file_path, "r") as f:
                    hashes = [line.strip() for line in f if line.strip()]
                if not hashes:
                    print("No hashes found in the text file.")
                else:
                    print(f"Loaded {len(hashes)} hashes from {file_path}.")
                return hashes
            else:
                print("[ERROR] Invalid selection. Please enter a valid number.")
        except ValueError:
            print("[ERROR] Invalid input. Please enter a number.")

