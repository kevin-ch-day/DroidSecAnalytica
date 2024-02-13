from database import DBFunct_ApkRecords, DBFunct_AnalysisRecords, DBRecordInserts
from utils import app_utils
from permission_analysis import permission_analyzer
from . import vt_androguard, vt_requests

def process_vt_response(response, analysis_name):
    try:
        analysis_id = DBFunct_AnalysisRecords.create_analysis_record(analysis_name)
        print(f"Analysis ID: {analysis_id}")
        andro_data = vt_androguard.androguard_data(response)
        if andro_data:
            process_androguard_data(analysis_id, andro_data)
        else:
            print("No Androguard data returned...")

        vt_data = vt_requests.parse_virustotal_response(response)
        if vt_data:
            apk_id = DBFunct_ApkRecords.get_apk_id_by_sha256(andro_data.get_sha256())
            DBRecordInserts.create_vt_engine_record(analysis_id, apk_id) 

            summary_stat = vt_data["Analysis Result"]["summary_statistics"]
            DBRecordInserts.update_vt_engine_detection(analysis_id, summary_stat)
   
            vendor_data = vt_data["Analysis Result"]["engine_detection"]
            DBRecordInserts.update_vt_engine_records(analysis_id, vendor_data)

            json_filename = "output\\" + andro_data.get_sha256() + "_json_data.txt"
            #vt_utils.save_json_response(vt_data, json_filename)

        DBFunct_AnalysisRecords.update_status_to_completed(analysis_id)

    except Exception as e:
        print(f"Error processing APK samples: {e}")

def process_permissions(analysis_id, apk_id, permissions):
    permissions_cnt = len(permissions)
    print(f"\nTotal Permissions: {permissions_cnt}")
    if permissions:
        for index in permissions:
            permission_analyzer.save_detected_permission(analysis_id, apk_id, permissions[index])
    else:
        print("No data.")

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
            #print(f"- {activity}") # Debugging
            DBRecordInserts.insert_vt_activities(analysis_id, activity, apk_id)
    else:
        print("No data.")

def process_services(analysis_id, apk_id, services):
    services_cnt = len(services)
    print(f"\nServices ({services_cnt}):")
    if services:
        for service in services:
            #print(f"- {service}") # Debugging
            DBRecordInserts.insert_vt_services(analysis_id, service, apk_id)
    else:
        print("No data.")

def process_receivers(analysis_id, apk_id, receivers):
    receivers_cnt = len(receivers)
    print(f"\nReceivers ({receivers_cnt}):")
    if receivers:
        for receiver in receivers:
            #print(f"- {receiver}") # Debugging
            DBRecordInserts.insert_vt_receivers(analysis_id, receiver, apk_id)
    else:
        print("No data.")

def process_libraries(analysis_id, apk_id, libraries):
    libraries_cnt = len(libraries)
    print(f"\nLibraries ({libraries_cnt}):")
    if libraries:
        for library in libraries:
            #print(f"- {library}") # Debugging
            DBRecordInserts.insert_vt_libraries(analysis_id, library, apk_id)
    else:
        print("No data.")

def process_androguard_data(analysis_id, andro_data):
    apk_id = DBFunct_ApkRecords.get_apk_id_by_sha256(andro_data.get_sha256())
    #print(f"APK ID: {apk_id}") # Debugging

    process_summary_data(analysis_id, andro_data)
    process_permissions(analysis_id, apk_id, andro_data.get_permissions())
    process_activities(analysis_id, apk_id, andro_data.get_activities())
    process_services(analysis_id, apk_id, andro_data.get_services())
    process_receivers(analysis_id, apk_id, andro_data.get_receivers())
    #process_libraries(analysis_id, apk_id, andro_data.get_libraries())

    footer = "=" * 50
    print(f"\n{footer}\n")

def process_apk_sample(record):
    print(f"Android APK ID: {record[0]} SHA-256: {record[1]}")
    hash_value = record[1]  # SHA256 hash value
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Test Run 2/12/2024"
    process_vt_response(response, analysis_name)

def run_analysis(iterative_mode=False):
    try:
        apk_records = DBFunct_ApkRecords.get_apk_records_sha256(237)
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

            #user_prompts.pause_until_keypress()

    except Exception as e:
        print(f"Error running the analysis: {e}")

def run_hash_ioc():
    hash_value = '57f8a57320eeed2f5b5a316d67319191ce717cc51384318966b61f95722e275f'
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Test Run #1 2/7/2024"
    process_vt_response(response, analysis_name)