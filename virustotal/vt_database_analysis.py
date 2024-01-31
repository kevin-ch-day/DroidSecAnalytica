# vt_database_analysis.py

from database import DBFunctions
from virustotal import vt_requests, vt_response, vt_utils
from utils import user_prompts

def test_virustotal_request():
    hash = "64ebe9b975de022b888f17db429af3a93d3db95db5af274e3eefd3ca7f24e350"
    response = vt_requests.query_hash(hash)
    print(response)

def process_apk_samples(apk_sample_records):
    print("\nProcessing APK Samples")
    try:
        for record in apk_sample_records:
            response = vt_requests.query_hash(record[5]) # SHA256 hash
            data = vt_response.parse_virustotal_response(response)
            user_prompts.pause_until_keypress()
    except Exception as e:
        print(f"Error processing APK samples: {e}")

def run_analysis():
    try:
        apk_records = DBFunctions.get_apk_samples()
        if not apk_records:
            print("No APK samples found in the database.")
            return

        process_apk_samples(apk_records)
    except Exception as e:
        print(f"Error running the analysis: {e}")
