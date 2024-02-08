from . import vt_response, vt_androguard
from database import DBFunct_ApkRecords, DBFunct_AnalysisRecords, DBFunct_Perm
from virustotal import vt_requests
from utils import user_prompts, app_utils

def process_vt_response(response, analysis_name):
    try:
        analysis_id = DBFunct_AnalysisRecords.create_analysis_record(analysis_name)
        print(f"Analysis ID: {analysis_id}")

        vt_data = vt_response.parse_virustotal_response(response)
        andro_data = vt_androguard.androguard_data(response)
        if andro_data:
            process_androguard_data(andro_data)
        else:
            print("No Androguard data returned...")

    except Exception as e:
        print(f"Error processing APK samples: {e}")

def process_androguard_data(andro_data):

    print(f"Package Name: {andro_data.get_package()}")
    print(f"Main Activity: {andro_data.get_main_activity()}")
    print(f"Target SDK Version: {andro_data.get_target_sdk_version()}")

    print(f"\nPermissions")
    for permission in andro_data.get_permissions():
        print(permission.name) 

    print("\nActivities")
    for activity in andro_data.get_activities():
        print(activity)

    print("\nServices")
    for service in andro_data.get_services():
        print(service)

    print("\nReceivers")
    for receiver in andro_data.get_receivers():
        print(receiver)

    print("\nLibraries")
    for library in andro_data.get_libraries():
        print(library)

    print("\nIntent Filters By Action")
    # for intent_filter in andro_data.get_intent_filters_by_action():
    #     print(intent_filter)

    print("\nIntent Filters By Category")
    # for intent_filter in andro_data.get_intent_filters_by_category():
    #     print(intent_filter)

def process_apk_permission(permission):
    try:
        permission_record = DBFunct_Perm.get_permission_record_by_name(permission.name)
        if permission_record:
            process_standard_permission(permission_record, permission)
        else:
            process_unknown_permission(permission)
    except Exception as e:
        print(f"Error processing permission {permission.name}: {e}")

def process_standard_permission(permission_record, permission):
    id = permission_record[0]
    DBFunct_Perm.check_standard_permission_record(id, permission.short_desc, permission.long_desc, permission.permission_type)

def process_unknown_permission(permission):
    try:
        unknown_permission_record = DBFunct_Perm.get_unknown_permission_record_by_name(permission.name)
        if unknown_permission_record:
            id = unknown_permission_record[0]
            print(f"Unknown Permission ID: {id}")
            DBFunct_Perm.check_unknown_permission_record(id, permission.short_desc, permission.long_desc, permission.permission_type)
        else:
            print("\n[**] Permission not found in database.")
            print("Name:\t\t", permission.name)
            print("Short Desc:\t", permission.short_desc)
            print("Long Desc:\t", permission.long_desc)
            print("Type:\t\t", permission.permission_type)
            DBFunct_Perm.insert_unknown_permission_record(permission.name, permission.short_desc, permission.long_desc, permission.permission_type)
            user_prompts.pause_until_keypress()
    except Exception as e:
        print(f"An error occurred while processing unknown permission: {e}")
    
def process_apk_sample(record):
    print(f"Processing APK Sample - ID: {record[0]}, SHA-256: {record[1]}")
    hash_value = record[1]  # SHA256 hash
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Test Run #1 2/7/2024"
    process_vt_response(response, analysis_name)

def run_analysis(iterative_mode=False):
    try:
        apk_records = DBFunct_ApkRecords.get_apk_records_sha256(92)
        if not apk_records:
            print("No APK samples found in the database.")
            return
        print("\nProcessing APK Samples")
        wait_time = 4 * 60 if iterative_mode else 0
        iteration = 0
        for record in apk_records:
            process_apk_sample(record)
            
            if iterative_mode and iteration == 4:
                iteration = 0
                app_utils.pause_with_updates(wait_time)
            else:
                iteration += 1

            user_prompts.pause_until_keypress()

    except Exception as e:
        print(f"Error running the analysis: {e}")

def run_hash_ioc():
    hash_value = '57f8a57320eeed2f5b5a316d67319191ce717cc51384318966b61f95722e275f'
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Test Run #1 2/7/2024"
    process_vt_response(response, analysis_name)
