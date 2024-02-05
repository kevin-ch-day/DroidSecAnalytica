# vt_database_analysis.py

from database import DBFunct_Perm, DBRecordInserts, DBFunct_ApkRecords
from virustotal import vt_requests, vt_response, vt_utils, vt_androguard
from utils import user_prompts, app_utils
import time

def process_apk_samples(apk_sample_records, iterative_mode=False):
    print("\nProcessing APK Samples")
    wait_time = 4 * 60 if iterative_mode else 0
    iteration = 0
    for record in apk_sample_records:
        process_apk_sample(record)
        
        if iterative_mode and iteration == 4:
            iteration = 0
            app_utils.pause_with_updates(wait_time)
        else:
            iteration += 1

        #user_prompts.pause_until_keypress()

def process_apk_sample(record):
    print(f"ID: {record[0]} SHA-256: {record[1]}")
    hash_value = record[1]  # SHA256 hash
    response = vt_requests.query_hash(hash_value)
    parsed_data = vt_response.parse_virustotal_response(response)
    
    # create vt_scan_analysis record

    for i in parsed_data['Analysis Result']['engine_detection']:
        engine = i[0]
        label = i[1]
    exit()

    andro_data = vt_androguard.androguard_data(response)
    if andro_data:
        permissions = andro_data.get_permissions()
        handle_detected_permissions(permissions)

def update_vendor_column(engine, label):
    pass


def run_analysis():
    try:
        apk_records = DBFunct_ApkRecords.get_apk_records_sha256()
        if not apk_records:
            print("No APK samples found in the database.")
            return
        process_apk_samples(apk_records, iterative_mode=False)
    except Exception as e:
        print(f"Error running the analysis: {e}")

def check_apk_sample_process(record_id):
    sha256 = DBFunct_ApkRecords.get_apk_record_sha256_by_id(record_id)
    process_apk_sample(sha256)
