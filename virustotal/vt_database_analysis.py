# vt_database_analysis.py

from database import DBFunctions
from virustotal import vt_requests, vt_response, vt_utils, vt_androguard
from utils import user_prompts
import time

def process_apk_samples(apk_sample_records, extended_mode=False):
    print("\nProcessing APK Samples")
    try:
        wait_time = 4 * 60 if extended_mode else 0
        iteration = 0

        for record in apk_sample_records:
            hash_value = record[5]  # SHA256 hash
            response = vt_requests.query_hash(hash_value)
            parsed_data = vt_response.parse_virustotal_response(response)
            andro_data = vt_androguard.androguard_data(response)
            permissions = andro_data.get_permissions()
            print(andro_data)

            print("\nPermissions:")
            i = 1
            for x in permissions:
                print(f" [{i}] {x.name}")
                i += 1
            
            exit()

            if extended_mode and iteration == 4:
                iteration = 0
                pause_with_progress(wait_time)
            else:
                input('Presss any key to continue...')
                iteration += 1

    except Exception as e:
        print(f"Error processing APK samples: {e}")

def pause_with_progress(wait_time, update_interval=1, display_text="Pausing..."):
    try:
        print(display_text)
        remaining_time = wait_time

        while remaining_time > 0:
            minutes, seconds = divmod(remaining_time, 60)
            time_display = f"Time remaining: {minutes:02d} minutes {seconds:02d} seconds"
            print(f"\r{time_display}", end="")
            time.sleep(update_interval)
            remaining_time -= update_interval

        print("\nPause completed.")
    except KeyboardInterrupt:
        print("\nPause interrupted by user.")
        raise

def test_virustotal_request():
    hash = "64ebe9b975de022b888f17db429af3a93d3db95db5af274e3eefd3ca7f24e350"
    response = vt_requests.query_hash(hash)
    print(response)

def run_analysis(extended_mode=False):
    try:
        apk_records = DBFunctions.get_apk_samples()
        if not apk_records:
            print("No APK samples found in the database.")
            return

        process_apk_samples(apk_records, extended_mode)
    except Exception as e:
        print(f"Error running the analysis: {e}")
