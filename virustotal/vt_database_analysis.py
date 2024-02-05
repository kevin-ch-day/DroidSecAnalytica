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

def handle_detected_permissions(permissions):
    known_permissions = list()
    unknown_permissions = list()
    for index in permissions:
        #print(f"\n{index.name}")
        #print(f"Type: {index.permission_type}")
        #print(f"Info: {index.short_desc}")
        #print(f"Desc: {index.long_desc}")

        # check if standard android permissions
        perm_id = DBFunct_Perm.get_permission_id_by_name(index.name)
        if perm_id:
            known_permissions.append((perm_id, index.name))
        
        # permission is non-standard or unknown
        else:
            unknown_id = DBFunct_Perm.get_unknown_permission_id(index.name)
            unknown_permissions.append([unknown_id, index])
            if not unknown_id:
                process_unknown_permission(index)
    
    # if unknown_permissions:
    #     print("\nUnknown permissions:")
    #     for index in unknown_permissions:
    #         print(index[1].name)

def process_unknown_permission(permission):
    #print(f"\nUnknown permission: {permission.name}")
    unknown_id = DBFunct_Perm.get_unknown_permission_id(permission.name)
    if not unknown_id:
        result = DBRecordInserts.insert_unknown_permission(permission)
        if not result:
            print("Failed to add permission.")

def add_permission(permission):
    result = DBRecordInserts.insert_android_permission(permission.name)
    if not result:
        print("Failed to add permission.")

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
