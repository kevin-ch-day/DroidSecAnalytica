from database import DBFunct_ApkRecords, DBFunct_AnalysisRecords, DBRecordInserts
from utils import user_prompts, app_utils
from permission_analysis import permission_analyzer

from . import vt_response, vt_androguard, vt_requests

def process_vt_response(response, analysis_name):
    try:
        analysis_id = DBFunct_AnalysisRecords.create_analysis_record(analysis_name)
        print(f"Analysis ID: {analysis_id}")

        vt_data = vt_response.parse_virustotal_response(response)
        andro_data = vt_androguard.androguard_data(response)
        if andro_data:
            process_androguard_data(analysis_id, andro_data)
        else:
            print("No Androguard data returned...")

        DBFunct_AnalysisRecords.update_status_to_completed(analysis_id)

    except Exception as e:
        print(f"Error processing APK samples: {e}")

def process_summary_data(analysis_id, andro_data):
    print("\nAndroid APK Analysis Report\n" + "=" * 50)
    print(f"MD5:                {andro_data.get_md5()}")
    print(f"SHA1:               {andro_data.get_sha1()}")
    print(f"SHA256:             {andro_data.get_sha256()}")
    print(f"Package Name:       {andro_data.get_package()}")
    print(f"Main Activity:      {andro_data.get_main_activity()}")
    print(f"Target SDK Version: {andro_data.get_target_sdk_version()}")
    print("-" * 50)

    DBRecordInserts.create_apk_analysis_records(
        analysis_id,
        andro_data.get_sha256(),
        andro_data.get_package(),
        andro_data.get_main_activity(),
        andro_data.get_target_sdk_version()
    )

def process_activities(analysis_id, apk_id, activities):
    activities_cnt = len(activities)
    print(f"\nActivities ({activities_cnt}):")
    if activities:
        for activity in activities:
            print(f"- {activity}")
            DBRecordInserts.insert_vt_activities(analysis_id, activity, apk_id)
    else:
        print("No data.")

def process_permissions(analysis_id, apk_id, permissions):
    permissions_cnt = len(permissions)
    print(f"\nPermissions ({permissions_cnt}):")
    if permissions:
        permission_analyzer.save_detected_permission(analysis_id, apk_id, permissions)
        for permission in permissions:
            print(f"- {permission}")
    else:
        print("No data.")

def process_services(analysis_id, apk_id, services):
    services_cnt = len(services)
    print(f"\nServices ({services_cnt}):")
    if services:
        for service in services:
            print(f"- {service}")
            DBRecordInserts.insert_vt_services(analysis_id, service, apk_id)
    else:
        print("No data.")

def process_receivers(analysis_id, apk_id, receivers):
    receivers_cnt = len(receivers)
    print(f"\nReceivers ({receivers_cnt}):")
    if receivers:
        for receiver in receivers:
            print(f"- {receiver}")
            DBRecordInserts.insert_vt_receivers(analysis_id, receiver, apk_id)
    else:
        print("No data.")

def process_libraries(analysis_id, apk_id, libraries):
    libraries_cnt = len(libraries)
    print(f"\nLibraries ({libraries_cnt}):")
    if libraries:
        for library in libraries:
            print(f"- {library}")
            DBRecordInserts.insert_vt_libraries(analysis_id, library, apk_id)
    else:
        print("No data.")

def process_androguard_data(analysis_id, andro_data):
    apk_id = DBFunct_ApkRecords.get_apk_id_by_sha256(andro_data.get_sha256())
    #print(f"APK ID: {apk_id}") # Debugging

    # Step 1: Process Summary Data
    process_summary_data(analysis_id, andro_data)
    
    # Step 2: Process Each Data Section Individually
    process_activities(analysis_id, apk_id, andro_data.get_activities())
    process_permissions(analysis_id, apk_id, andro_data.get_permissions())
    process_services(analysis_id, apk_id, andro_data.get_services())
    process_receivers(analysis_id, apk_id, andro_data.get_receivers())
    process_libraries(analysis_id, apk_id, andro_data.get_libraries())

    print("=" * 50)

def process_apk_sample(record):
    print(f"Processing APK Sample - ID: {record[0]}, SHA-256: {record[1]}")
    hash_value = record[1]  # SHA256 hash
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Test Run #1 2/7/2024"
    process_vt_response(response, analysis_name)

def run_analysis(iterative_mode=True):
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