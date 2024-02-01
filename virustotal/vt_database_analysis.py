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
        process_single_apk_sample(record)

        if iterative_mode and iteration == 4:
            iteration = 0
            pause_with_progress(wait_time)
        else:
            input('Press any key to continue...')
            iteration += 1

def process_single_apk_sample(record):
    hash_value = record[1]  # SHA256 hash
    response = vt_requests.query_hash(hash_value)
    parsed_data = vt_response.parse_virustotal_response(response)
    andro_data = vt_androguard.androguard_data(response)
    permissions = andro_data.get_permissions()
    print(andro_data)

    print("\nPermissions:")
    for permission in permissions:
        handle_permission(permission)

def handle_permission(permission):
    perm_id = DBFunctions.get_permission_id_by_name(permission.name)
    if perm_id:
        print(f" [{perm_id}] {permission.name}")
    else:
        process_unknown_permission(permission)

def process_unknown_permission(permission):
    print(f"\nUnknown permission: {permission.name}")
    while True:  # Keep asking until a valid choice is made
        print("\nWhat would you like to do with this unknown permission?")
        print("1. Add to main permission table")
        print("2. Record as unknown permission")
        print("3. Skip")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            add_permission(permission)
            break
        
        elif choice == '2':
            record_as_unknown_permission(permission)
            break

        elif choice == '3':
            break

        else:
            print("Invalid choice, please enter 1, 2, or 3.")

def add_permission(permission):
    # This function needs to be defined or updated accordingly
    add_permission_result = DBFunctions.add_permission(permission.name)
    if add_permission_result:
        print(f"Permission added to the main permission table.")
    else:
        print(f"Failed to add permission.")

def record_as_unknown_permission(permission):
    unknown_id = DBFunctions.get_unknown_permission_id(permission.name)
    if not unknown_id:
        result = DBRecordInserts.insert_unknown_permission(permission.name)
        if result:
            print(f"Unknown permission recorded.")
        else:
            print(f"Failed to record unknown permission.")

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

def run_analysis():
    try:
        apk_records = DBFunctions.get_apk_samples_sha256()
        if not apk_records:
            print("No APK samples found in the database.")
            return

        process_apk_samples(apk_records, iterative_mode=False)
    except Exception as e:
        print(f"Error running the analysis: {e}")
