# data_processing.py

import datetime
import hashlib
import json
import os
import calendar
import re
import logging

from . import app_display

def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S'):
    # Formats a Unix timestamp into a readable date string
    try:
        return datetime.datetime.fromtimestamp(int(timestamp)).strftime(format)
    except ValueError:
        return 'Invalid Timestamp format.'

def extract_metadata(file_data):
    # Extracts file metadata, handling missing values
    metadata = {
        'File Type': file_data.get('type', 'Unknown'),
        'Upload Date': file_data.get('upload_date', 'Unknown'),
        # Additional metadata fields
    }
    return metadata

def structured_output(data):
    # Formats data into a structured JSON string for output
    try:
        return json.dumps(data, indent=4)
    except TypeError:
        return 'Error in data formatting.'

# Function to format a timestamp as a date string
def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S'):
    try:
        formatted_date = datetime.datetime.fromtimestamp(int(timestamp)).strftime(format)
        print(f"Formatted Timestamp: {formatted_date}")
        return formatted_date
    except ValueError:
        print("Invalid Timestamp")
        return 'Invalid Date'

def calculate_hashes(apk_file_path):
    # Check if the file is an APK file
    if not apk_file_path.lower().endswith('.apk'):
        print("The provided file is not an APK file.")
        return False

    hashes = {"MD5": None, "SHA1": None, "SHA256": None}
    try:
        with open(apk_file_path, 'rb') as file:
            file_data = file.read()

        # Calculate and store hashes
        hashes["MD5"] = hashlib.md5(file_data).hexdigest()
        hashes["SHA1"] = hashlib.sha1(file_data).hexdigest()
        hashes["SHA256"] = hashlib.sha256(file_data).hexdigest()

        # Display the hashes
        print("\nAPK Calculated Hashes")
        print("-" * 60)
        print(f"File  : {os.path.basename(apk_file_path)}")
        for hash_type, hash_value in hashes.items():
            print(f"{hash_type:6}: {hash_value}")
        print("-" * 60)

    except FileNotFoundError:
        print(f"Error: The file '{apk_file_path}' does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return hashes

# Function to extract MD5, SHA1, and SHA256 hashes from a response
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

# Function to calculate vote statistics
def calculate_vote_statistics(last_analysis_stats):
    statistics = {
        "Malicious Votes": last_analysis_stats.get("malicious", 0),
        "Harmless Votes": last_analysis_stats.get("harmless", 0),
        "Suspicious Votes": last_analysis_stats.get("suspicious", 0),
        "Undetected Votes": last_analysis_stats.get("undetected", 0)
    }
    statistics["Total Votes"] = sum(last_analysis_stats.values())
    if statistics["Total Votes"] > 0:
        statistics["Malicious Percentage"] = "{:.2f}%".format(
            (statistics["Malicious Votes"] / statistics["Total Votes"]) * 100
        )
    else:
        statistics["Malicious Percentage"] = "N/A"
    print(f"Vote Statistics: {statistics}")
    return statistics

# Function to extract file metadata
def extract_file_metadata(response_data):
    attributes = response_data.get("data", {}).get("attributes", {})
    first_submission_timestamp = attributes.get("first_submission_date")
    upload_date = format_timestamp(first_submission_timestamp) if first_submission_timestamp else "Unknown"
    last_analysis_timestamp = attributes.get("last_analysis_date")
    latest_report_date = format_timestamp(last_analysis_timestamp) if last_analysis_timestamp else "Unknown"
    reputation = attributes.get("reputation", "N/A")
    file_type = attributes.get("type_description", "Unknown")
    metadata = {
        "File Type": file_type,
        "Upload Date": upload_date,
        "Latest Report": latest_report_date,
        "Community Reputation": reputation
    }
    print(f"Extracted File Metadata: {metadata}")
    return metadata

# Function to classify the threat based on vote statistics
def classify_threat(vote_stats):
    if vote_stats["Malicious Votes"] > vote_stats["Harmless Votes"]:
        classification = "Potentially Malicious"
    elif vote_stats["Suspicious Votes"] > vote_stats["Harmless Votes"]:
        classification = "Suspicious"
    else:
        classification = "Likely Safe"
    print(f"Threat Classification: {classification}")
    return classification

# Function to extract detailed scan results
def extract_detailed_scan_results(last_analysis_results):
    detailed_results = []
    for engine, result in last_analysis_results.items():
        detailed_results.append(f"- {engine}: {result.get('result', 'N/A')}")
    print(f"Detailed Scan Results: {detailed_results}")
    return {"Detailed Scan Results": detailed_results}

# Function to extract and analyze data
def extract_and_analyze_data(response):
    # Extract relevant data from the response
    file_data = response.get("data", {}).get("attributes", {})
    last_analysis_stats = file_data.get("last_analysis_stats", {})
    last_analysis_results = file_data.get("last_analysis_results", {})

    # Initialize an empty analysis dictionary
    analysis = {}

    # Extract and update hash information
    analysis.update(extract_hashes(response))

    # Extract and update file metadata
    analysis.update(extract_file_metadata(file_data))

    # Calculate and update vote statistics
    analysis.update(calculate_vote_statistics(last_analysis_stats))

    # Classify the threat based on vote statistics
    analysis["Classification"] = classify_threat(analysis)

    # Extract and update detailed scan results
    analysis.update(extract_detailed_scan_results(last_analysis_results))

    return analysis

def analyze_data(data):
    total_scans = len(data['data']['attributes']['last_analysis_results'])
    malicious_count = sum(1 for result in data['data']['attributes']['last_analysis_results'].values() if result['category'] == 'malicious')
    benign_count = total_scans - malicious_count
    detection_ratio = malicious_count / total_scans if total_scans > 0 else 0.0

    analysis_results = {
        'Total Scans': total_scans,
        'Malicious Count': malicious_count,
        'Benign Count': benign_count,
        'Detection Ratio': detection_ratio,
    }
    print(f"Analysis Results: {analysis_results}")
    return analysis_results

def determine_hash_fields(hash_str):
    hash_lengths = {"MD5": 32, "SHA1": 40, "SHA256": 64}

    # Handle None or empty string input
    if not hash_str:
        print('Error: No hash string provided. The input is empty or None.')
        return None, None, None

    # Validate hash string for hexadecimal characters
    if not all(c in '0123456789abcdefABCDEF' for c in hash_str):
        print(f'Error: Invalid hash string: "{hash_str}". Hash must be hexadecimal.')
        return None, None, None

    # Determine the type of hash based on its length
    for hash_type, length in hash_lengths.items():
        if len(hash_str) == length:
            return (hash_str if hash_type == "MD5" else None,
                    hash_str if hash_type == "SHA1" else None,
                    hash_str if hash_type == "SHA256" else None)

    print(f'Error: Invalid hash string length: "{hash_str}". Unrecognized hash type.')
    return None, None, None

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

        app_display.display_hashes(apk_file_path, hashes)

    except FileNotFoundError:
        print(f"Error: The file '{apk_file_path}' does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return hashes

def parse_file(file_path):
    """ Parse data from a given file and return structured malware data. """
    logging.info('Parsing file: ' + file_path)
    month_mapping = generate_month_mapping()
    simplified_file_path = simplify_file_path(file_path)

    try:
        lines = read_file_lines(file_path)
        return process_lines(lines, month_mapping, simplified_file_path)
    except Exception as e:
        logging.error(f'Error reading {file_path}: {e}')
        return []

def process_lines(lines, month_mapping, file_path):
    """ Process file lines and return structured malware data. """
    malware_data = []
    current_month = None
    malware_name = None

    for line_number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line: 
            continue  # Skip empty lines

        # month
        if line.startswith('**'):
            current_month = update_month(line, month_mapping, current_month)
            logging.debug(f'Updated month at line {line_number}: {current_month}')

        # malware name
        elif line.startswith('-'):
            malware_name = update_malware_name(line, malware_name)
            logging.debug(f'Updated malware id at line {line_number}: {malware_name}')

        elif malware_name:
            try:
                malware_entry = parse_malware_entry(line, malware_name, file_path, current_month)
                if malware_entry:
                    malware_data.append(malware_entry)
                    logging.debug(f'Malware entry added from line {line_number}: {malware_entry}')
            except ValueError as e:
                logging.error(f"Error at line {line_number} in file {file_path}: {e}")
                logging.error(f"Problematic data: '{line}'")

    if not malware_data:
        logging.warning(f'No valid malware data extracted from file: {file_path}')

    return malware_data

def parse_malware_entry(line, name, file_path, month):
    """ Parse a single line of malware data and return a structured entry. """
    # Extract the file name from the file path
    file_name = file_path.split('/')[-1]

    # Check if the file name matches the 'YYYY-README.txt' format and extract the year
    year_match = re.match(r'(\d{4})-README\.txt', file_name)
    year = year_match.group(1) if year_match else None

    # Assuming the hash strings don't have a specific prefix and are direct hash values.
    md5, sha1, sha256 = determine_hash_fields(line)
    if any([md5, sha1, sha256]):
        # Return the structured entry, including the year (or None if not found)
        return name, name, md5, sha1, sha256, file_path, month, year
    else:
        raise ValueError(f"Invalid hash string: '{line}'")

def generate_month_mapping():
    """ Generate a mapping from abbreviated to full month names. """
    return {month: calendar.month_name[i] for i, month in enumerate(calendar.month_abbr) if month}

def simplify_file_path(file_path):
    """ Simplify the file path for easier processing. """
    return file_path.replace('input/', '')

def update_month(line, month_mapping, current_month):
    """ Update and return the current month based on the line content. """
    if line.startswith('**'):
        month_str = line.strip('*').strip()
        return month_mapping.get(month_str, month_str)
    return current_month

def update_malware_name(line, name):
    """ Update and return the current malware name based on the line content. """
    if line.startswith('-'):
        return line.strip('-').strip()
    return name