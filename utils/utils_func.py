import hashlib
import os
import re

def format_size(bytes_value):
    """
    Converts a size in bytes to a human-readable format (KB, MB, GB).
    """
    if bytes_value < 1024:
        return f"{bytes_value} B"
    elif bytes_value < 1024 ** 2:
        return f"{bytes_value / 1024:.2f} KB"
    elif bytes_value < 1024 ** 3:
        return f"{bytes_value / (1024 ** 2):.2f} MB"
    else:
        return f"{bytes_value / (1024 ** 3):.2f} GB"

def read_hash_file_data(filepath):
    print(f"Reading hash data from {filepath}...")
    try:
        with open(filepath, 'r') as file:
            hashes = [line.strip() for line in file if line.strip()]
        
        print(f"Successfully read {len(hashes)} hash(es).")
        return hashes
    
    except FileNotFoundError:
        print("[Error] The specified hash data file was not found.")
    
    except Exception as e:
        print(f"[Error] An unexpected error occurred while reading the file: {e}")
    
    return None

def is_valid_sha256(hash_str: str) -> bool:
    return bool(re.fullmatch(r'^[a-fA-F0-9]{64}$', hash_str))

def calculate_hashes(apk_file_path):
    # Check if the file is an APK file
    if not apk_file_path.lower().endswith('.apk'):
        print("Error: The provided file is not an APK file.")
        return None

    hash_types = ["MD5", "SHA1", "SHA256"]
    hashes = {}

    try:
        with open(apk_file_path, 'rb') as file:
            file_data = file.read()

        # Calculate and store hashes
        for hash_type in hash_types:
            hash_value = hashlib.new(hash_type.lower(), file_data).hexdigest()
            hashes[hash_type] = hash_value

        display_hashes(apk_file_path, hashes)

    except FileNotFoundError:
        print(f"Error: The file '{apk_file_path}' does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return hashes

def extract_hashes(response_data):
    attributes = response_data.get("data", {}).get("attributes", {})
    md5 = attributes.get("md5", "N/A")
    sha1 = attributes.get("sha1", "N/A")
    sha256 = attributes.get("sha256", "N/A")
    print(f"Extracted Hashes - MD5: {md5}, SHA1: {sha1}, SHA256: {sha256}")
    return {
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256
    }

def determine_hash_type(hash_str):
    """Determine the hash type based on its length."""
    hash_lengths = {32: 'md5', 40: 'sha1', 64: 'sha256'}
    return hash_lengths.get(len(hash_str), None)

def determine_hash_fields(hash_str):
    if not hash_str:
        print('Error: No hash string provided. The input is empty or None.')
        return None, None, None

    # Validate hash string for hexadecimal characters
    if not all(c in '0123456789abcdefABCDEF' for c in hash_str):
        print(f'Error: Invalid hash string: "{hash_str}". Hash must be hexadecimal.')
        return None, None, None

    # Determine the type of hash based on its length
    hash_lengths = {"MD5": 32, "SHA1": 40, "SHA256": 64}
    for hash_type, length in hash_lengths.items():
        if len(hash_str) == length:
            return (hash_str if hash_type == "MD5" else None,
                    hash_str if hash_type == "SHA1" else None,
                    hash_str if hash_type == "SHA256" else None)

    print(f'Error: Invalid hash string length: "{hash_str}". Unrecognized hash type.')
    return None, None, None

def display_hashes(file_path, hashes):
    print("\nAPK Calculated Hashes")
    print("-" * 60)
    print(f"File  : {os.path.basename(file_path)}")
    for hash_type, hash_value in hashes.items():
        print(f"{hash_type:6}: {hash_value}")
    print("-" * 60)