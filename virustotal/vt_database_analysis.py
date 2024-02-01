# vt_database_analysis.py

from database import DBFunctions, DBRecordInserts
from virustotal import vt_requests, vt_response, vt_utils, vt_androguard
from utils import user_prompts
import time

def process_apk_samples(apk_sample_records, iterative_mode=False):
    print("\nProcessing APK Samples")
    wait_time = 4 * 60 if iterative_mode else 0
    iteration = 0

    for record in apk_sample_records:
        process_apk_sample(record)
        
        if iterative_mode and iteration == 4:
            iteration = 0
            pause_with_progress(wait_time)
        else:
            iteration += 1

        user_prompts.pause_until_keypress()

def process_apk_sample(record):
    print(f"ID: {record[0]} SHA-256: {record[1]}")
    hash_value = record[1]  # SHA256 hash
    response = vt_requests.query_hash(hash_value)
    parsed_data = vt_response.parse_virustotal_response(response)
    andro_data = vt_androguard.androguard_data(response)
    if andro_data:
        #permissions = andro_data.get_permissions()
        print(andro_data)
        #print(permissions)
    
    
    #handle_detected_permissions(permissions)

def handle_detected_permissions(permissions):
    known_permissions = list()
    unknown_permissions = list()
    for index in permissions:
        perm_id = DBFunctions.get_permission_id_by_name(index.name)
        if perm_id:
            known_permissions.append((perm_id, index.name))
        else:
            unknown_id = DBFunctions.get_unknown_permission_id(index.name)
            unknown_permissions.append([unknown_id, index])
            if not unknown_id:
                process_unknown_permission(index)

    # if known_permissions:
    #     print("\nPermissions:")
    #     for index in known_permissions:
    #         print(f" [{index[0]}] {index[1]}")
    
    if unknown_permissions:
        print("\nUnknown permissions:")
        for index in unknown_permissions:
            print(f" [{index[0]}] {index[1].name} {index[1].permission_type}") # PermissionADT Object

def process_unknown_permission(permission):
    print(f"\nUnknown permission: {permission.name}")
    while True:
        print("\nWhere should this permission record be saved?")
        print("1. Main permission table")
        print("2. Unknown permission table")
        print("3. Skip")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            add_permission(permission)
            break
        
        elif choice == '2':
            record_unknown_permission(permission)
            break

        elif choice == '3':
            break

        else:
            print("Invalid choice, please enter 1, 2, or 3.")

def add_permission(permission):
    # This function needs to be defined or updated accordingly
    add_permission_result = DBRecordInserts.insert_android_permission(permission.name)
    if add_permission_result:
        print("Permission added.")
    else:
        print("Failed.")

def record_unknown_permission(permission):
    unknown_id = DBFunctions.get_unknown_permission_id(permission.name)
    if not unknown_id:
        result = DBRecordInserts.insert_unknown_permission(permission.name)
        if result:
            print("Permission added.")
        else:
            print("Failed.")

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

def alpha():
    try:
        apk_records = DBFunctions.get_apk_samples_sha256()
        if not apk_records:
            print("No APK samples found in the database.")
            return
        process_apk_samples(apk_records, iterative_mode=False)
    except Exception as e:
        print(f"Error running the analysis: {e}")

def check_apk_sample_process():
    record_id = 11
    sha256 = DBFunctions.get_apk_record_sha256_by_id(record_id, 12)
    process_apk_sample(sha256)

def run_analysis():
    try:
        alpha()
        #check_apk_sample_process()
    except Exception as e:
        print(f"Error running the analysis: {e}")