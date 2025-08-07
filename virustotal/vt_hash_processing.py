# vt_hash_processing.py

from database import db_get_records
from . import vt_requests, vt_data_processor

def check_unanalyzed_hashes():
    """Checks the database for unanalyzed hashes and processes them using VirusTotal."""
    
    print("Checking database for unanalyzed hashes...")
    results = db_get_records.get_unanalyzed_database_hashes()

    # Ensure results is a list or tuple before processing
    if not isinstance(results, (list, tuple)):
        print("Error: Failed to retrieve unanalyzed hashes or received invalid data.")
        return

    num_records = len(results)
    if num_records == 0:
        print("No unanalyzed hashes found.")
        return

    print(f"Number of unanalyzed records: {num_records}")

    for index, sha256_hash in enumerate(results, start=1):
        print(f"\nProcessing: {index} of {num_records} records.")
        print(f"Hash: {sha256_hash}\n")
        try:
            response = vt_requests.query_virustotal(sha256_hash, "hash")
            vt_data_processor.process_vt_response(response, "hash")

        except Exception as e:
            print(f"Error processing {sha256_hash}: {e}")

    print("Finished processing unanalyzed hashes.")
