# vt_database_analysis.py

from database import DBFunctions, DBRecordInserts
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
    andro_data = vt_androguard.androguard_data(response)
    if andro_data:
        permissions = andro_data.get_permissions()
        handle_detected_permissions(permissions)

def handle_detected_permissions(permissions):
    known_permissions = list()
    unknown_permissions = list()
    for index in permissions:
        #print(f"\n{index.name}")
        #print(f"Type: {index.permission_type}")
        #print(f"Info: {index.short_desc}")
        #print(f"Desc: {index.long_desc}")

        # check if standard android permissions
        perm_id = DBFunctions.get_permission_id_by_name(index.name)
        if perm_id:
            known_permissions.append((perm_id, index.name))
        
        # permission is non-standard or unknown
        else:
            unknown_id = DBFunctions.get_unknown_permission_id(index.name)
            unknown_permissions.append([unknown_id, index])
            if not unknown_id:
                process_unknown_permission_v2(index)
    
    # if unknown_permissions:
    #     print("\nUnknown permissions:")
    #     for index in unknown_permissions:
    #         print(index[1].name)

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
            unknown_id = DBFunctions.get_unknown_permission_id(permission.name)
            if not unknown_id:
                result = DBRecordInserts.insert_unknown_permission(permission.name)
                if not result:
                    print("Failed to add permission.")
            break

        elif choice == '3':
            break

        else:
            print("Invalid choice, please enter 1, 2, or 3.")
            
def process_unknown_permission_v2(permission):
    #print(f"\nUnknown permission: {permission.name}")
    unknown_id = DBFunctions.get_unknown_permission_id(permission.name)
    if not unknown_id:
        result = DBRecordInserts.insert_unknown_permission(permission)
        if not result:
            print("Failed to add permission.")

def add_permission(permission):
    result = DBRecordInserts.insert_android_permission(permission.name)
    if not result:
        print("Failed to add permission.")

def alpha():
    try:
        apk_records = DBFunctions.get_apk_records_sha256(422)
        if not apk_records:
            print("No APK samples found in the database.")
            return
        process_apk_samples(apk_records, iterative_mode=False)
    except Exception as e:
        print(f"Error running the analysis: {e}")

def beta():
    file_path = "output/unknown_permissions_output.txt"
    results = DBFunctions.check_uknown_permissions_alpha()    
    with open(file_path, 'w') as file:
        for perm_id, constant_value in results:
            file.write(f"ID: {perm_id} {constant_value}\n")
    print(f"Results have been written to {file_path}")

def check_apk_sample_process(record_id):
    sha256 = DBFunctions.get_apk_record_sha256_by_id(record_id)
    process_apk_sample(sha256)

def run_analysis():
    try:
        alpha()
        #beta()
        #check_apk_sample_process(12)
    except Exception as e:
        print(f"Error running the analysis: {e}")