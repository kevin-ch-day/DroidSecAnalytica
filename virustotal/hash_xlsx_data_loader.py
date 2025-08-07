# hash_xlsx_data_loader.py

import pandas as pd
import datetime
import time

from . import vt_requests
from utils import utils_func
from database import db_get_records, db_insert_records

# Hardcoded file path
FILE_PATH = "input\\new_malware_samples.xlsx"

def format_timestamp(ts):
    """Converts Unix timestamp to human-readable date format (YYYY-MM-DD)."""
    if isinstance(ts, (int, float)) and ts > 0:
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
    return ts  # Return as is if it's not a valid timestamp

def read_excel_file():
# Reads hash data from the Excel file and returns it as a DataFrame.

    print(f"\nReading hash data from {FILE_PATH}...")

    try:
        df = pd.read_excel(FILE_PATH, engine="openpyxl", dtype=str)
        df = df.dropna(how="all")  # Remove empty rows
        return df

    except Exception as e:
        print(f"[ERROR] Failed to read the Excel file: {e}")
        return None

def extract_hashes(df):
# Extracts and structures hash data from the DataFrame.
    if df is None or df.empty:
        print("[WARNING] No valid data found in the Excel file.")
        return []

    # If only one column exists, assume it's a hash list
    if df.shape[1] == 1:
        hash_column = df.columns[0]
        hashes = df[hash_column].dropna().tolist()
        print(f"[SUCCESS] Loaded {len(hashes)} standalone hashes.")
        return [{"Family": "Unknown", "Name": "Unknown", "Hash": h} for h in hashes]

    # If multiple columns exist, validate required fields
    required_columns = {"Family", "Name", "Hash"}
    if not required_columns.issubset(df.columns):
        missing_cols = required_columns - set(df.columns)
        raise ValueError(f"[ERROR] Missing required columns: {missing_cols}")

    df = df.dropna(subset=["Family", "Name", "Hash"])  # Drop incomplete rows

    # Process structured data
    structured_hashes = [
        {"Family": row["Family"].strip(), "Name": row["Name"].strip(), "Hash": row["Hash"].strip().lower()}
        for _, row in df.iterrows()
    ]

    print(f"Processed {len(structured_hashes)} structured hash entries.")
    return structured_hashes

def process_hash_records(hash_records):
    # Manages the overall VirusTotal hash analysis workflow

    if not hash_records:
        print("No hashes to analyze.")
        return

    total_records = len(hash_records)
    processed_records = 0
    batch_counter = 0  # Track API calls per batch (10 requests per batch)

    print(f"Total records to process: {total_records}\n")

    for index, record in enumerate(hash_records, start=1):
        # Extract hash details
        hash_value, family, name = extract_hash_info(record)

        if not hash_value:
            print(f"Skipping entry {index} with missing hash.")
            continue

        # Fetch data from VirusTotal API
        print("Fetch data from VirusTotal API")
        data = fetch_virustotal_data(hash_value)

        if not data:
            print("[Error] No data returned..")
            batch_counter += 1
            continue  # Skip to the next hash

        # Parse relevant attributes from VirusTotal response
        parsed_data = parse_virustotal_response(data)

        # Print analysis summary
        print_analysis_summary(index, total_records, family, name, parsed_data)

        # Store data in the database
        store_hash_analysis_results(parsed_data, family, name)

        # Update progress
        processed_records += 1
        percent_remaining = ((total_records - processed_records) / total_records) * 100
        print(f"\nProgress: {processed_records}/{total_records} records processed {percent_remaining:.2f}% remaining.")
        print("=" * 50)

        # API Rate Limit Handling: Pause every 10 requests
        batch_counter += 1
        if batch_counter >= 10:
            print("\nPausing for 60 seconds to comply with VirusTotal API rate limits...")
            time.sleep(60)  # Pause execution for 60 seconds
            batch_counter = 0  # Reset counter after pause

def extract_hash_info(record):
    # Extracts basic hash details from the record
    family = record.get("Family", "Unknown")
    name = record.get("Name", "Unknown")
    hash_value = record.get("Hash")
    return hash_value, family, name

def fetch_virustotal_data(hash_value):
    # Queries the VirusTotal API and returns the response data
    response = vt_requests.query_virustotal(hash_value, "hash")
    return response.get("data", {})

def parse_virustotal_response(data):
    # Extracts relevant attributes from the VirusTotal API response

    attributes = data.get("attributes", {})

    return {
        "md5": attributes.get("md5", "Unknown"),
        "sha1": attributes.get("sha1", "Unknown"),
        "sha256": attributes.get("sha256", "Unknown"),
        "virustotal_url": data.get("links", {}).get("self", "N/A"),
        "threat_label": attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown"),
        "sample_size": attributes.get("size", 0),
        "formatted_sample_size": utils_func.format_size(attributes.get("size", 0)) if isinstance(attributes.get("size", 0), int) else "N/A",
        "type_extension": attributes.get("type_extension", "N/A"),
        "type_description": attributes.get("type_description", "N/A"),
        "formatted_submission_date": format_timestamp(attributes.get("first_submission_date")) if isinstance(attributes.get("first_submission_date"), int) else "N/A",
        "formatted_itw_date": format_timestamp(attributes.get("first_seen_itw_date")) if isinstance(attributes.get("first_seen_itw_date"), int) else None  # Ensure NULL if missing
    }

def print_analysis_summary(index, total_records, family, name, parsed_data):
    # Prints an organized summary of the VirusTotal analysis result

    print("\n" + "=" * 70)
    print(f"VIRUSTOTAL ANALYSIS | RECORD {index}/{total_records} ({(index/total_records)*100:.2f}% Complete)")
    print("=" * 70)

    # Malware Information
    print("\nMalware Details")
    print("-" * 70)
    print(f"Family           : {family}")
    print(f"Name             : {name}")
    print(f"Classification   : {parsed_data['threat_label']}")
    
    # Hash Information
    print("\nFile Hashes")
    print("-" * 70)
    print(f"MD5              : {parsed_data['md5']}")
    print(f"SHA1             : {parsed_data['sha1']}")
    print(f"SHA256           : {parsed_data['sha256']}")
    
    print(f"\nVirusTotal URL   : {parsed_data['virustotal_url']}")
    print(f"First Submission: {parsed_data['formatted_submission_date']}")
    
    if parsed_data["formatted_itw_date"]:
        print(f"First Seen in the Wild: {parsed_data['formatted_itw_date']}")

    # File Size & Type
    print("\nFile Information")
    print("-" * 70)
    print(f"Raw Size         : {parsed_data['sample_size']} bytes")
    print(f"Formatted Size   : {parsed_data['formatted_sample_size']}")
    print(f"Type Extension   : {parsed_data['type_extension']}")
    print(f"Type Description : {parsed_data['type_description']}")

    print("=" * 70)

def store_hash_analysis_results(parsed_data, family, name):
    # Stores the VirusTotal analysis results in the database

    print("\nChecking database records...")

    # Check if the hash already exists in the hash_data_ioc table
    if not db_get_records.check_hash_exists(parsed_data["md5"], parsed_data["sha1"], parsed_data["sha256"]):
        print("Adding entry to 'hash_data_ioc' table...")
        db_insert_records.add_hash_ioc_record(parsed_data["md5"], parsed_data["sha1"], parsed_data["sha256"])
    else:
        print("Entry already exists in 'hash_data_ioc' table. Skipping.")

    # Check if the hash already exists in the malware_samples table
    if not db_get_records.get_apk_id_by_sha256(parsed_data["sha256"]):
        print("Adding entry to 'malware_samples' table...")
        db_insert_records.store_malware_sample(
            name, family, parsed_data["threat_label"], parsed_data["md5"], parsed_data["sha1"], parsed_data["sha256"],
            parsed_data["sample_size"], parsed_data["formatted_sample_size"], parsed_data["formatted_itw_date"],
            parsed_data["formatted_submission_date"], parsed_data["type_description"], parsed_data["virustotal_url"]
        )
    else:
        print("Entry already exists in 'malware_samples' table. Skipping.")

def run_xlxs_data_loader():
    df = read_excel_file()
    hash_records = extract_hashes(df)
    process_hash_records(hash_records)