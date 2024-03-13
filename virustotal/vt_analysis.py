# vt_analysis.py

from database import DB_AnalysisRecords, DB_ApkRecords, DBRecordInserts
from utils import app_utils, hash_utils
from permission_audit import save_permissions
from . import vt_androguard, vt_requests

def process_vt_response(response, analysis_name):
    try:
        analysis_id = DB_AnalysisRecords.create_analysis_record(analysis_name)
        print(f"Analysis ID: {analysis_id}")
        
        andro_data = vt_androguard.handle_androguard_response(response)
        if andro_data:
            process_androguard_data(analysis_id, andro_data)
        else:
            print("No Androguard data returned...")

        vt_data = vt_requests.parse_virustotal_response(response)
        if vt_data:
            apk_id = DB_ApkRecords.get_apk_id_by_sha256(andro_data.get_sha256())

            print(f"\nCreating Virustotal engine record..")
            DBRecordInserts.create_vt_engine_record(analysis_id, apk_id) 

            summary_stat = vt_data["Analysis Result"]["summary_statistics"]
            #print(f"{summary_stat}\n") # DEBUGGING
            print(f"Adding summary stats.")
            DBRecordInserts.update_vt_engine_detection(analysis_id, summary_stat)
   
            vendor_data = vt_data["Analysis Result"]["engine_detection"]
            #print(f"{vendor_data}") # DEBUGGING
            print(f"Adding engine results.")
            DBRecordInserts.update_vt_engine_records(analysis_id, vendor_data)

            # Saving json response
            #json_filename = "output\\" + andro_data.get_sha256() + "_json_data.txt"
            #vt_utils.save_json_response(vt_data, json_filename)

        DB_AnalysisRecords.update_status_to_completed(analysis_id)
        #user_prompts.pause_until_keypress()
        print()

    except Exception as e:
        print(f"Error processing APK samples: {e}")

def process_permissions(analysis_id, apk_id, permissions):
    permissions_cnt = len(permissions)
    print(f"\nPermissions: {permissions_cnt}")
    if permissions:
        for index in permissions:
            save_permissions.save_detected_permission(analysis_id, apk_id, permissions[index])
    else:
        print("No data.")

def process_metadata(analysis_id, andro_data):    
    # Retrieve data with checks for None values or defaulting to 'Not Available'
    md5 = andro_data.get_md5() or 'Not Available'
    sha1 = andro_data.get_sha1() or 'Not Available'
    sha256 = andro_data.get_sha256() or 'Not Available'
    package_name = andro_data.get_package() or 'Not Available'
    main_activity = andro_data.get_main_activity() or 'Not Available'
    target_sdk_version = andro_data.get_target_sdk_version() or 'Not Available'
    
    # Display the retrieved information
    print(f"MD5:                {md5}")
    print(f"SHA1:               {sha1}")
    print(f"SHA256:             {sha256}")
    print(f"Package Name:       {package_name}")
    print(f"Main Activity:      {main_activity}")
    print(f"Target SDK Version: {target_sdk_version}")
    
    # Attempt to insert the record into the database with error handling
    try:
        DBRecordInserts.create_apk_analysis_records(
            analysis_id, sha256, package_name, main_activity, target_sdk_version
        )
    
    except Exception as e:
        print(f"\nFailed to insert record into the database. Error: {e}")

def process_activities(analysis_id, apk_id, activities):
    activities_cnt = len(activities)
    print(f"\nActivities ({activities_cnt})")
    if activities:
        for activity in activities:
            #print(f"- {activity}") # Debugging
            DBRecordInserts.insert_vt_activities(analysis_id, activity, apk_id)
    else:
        print("No data.")

def process_services(analysis_id, apk_id, services):
    services_cnt = len(services)
    print(f"\nServices ({services_cnt})")
    if services:
        for service in services:
            #print(f"- {service}") # Debugging
            DBRecordInserts.insert_vt_services(analysis_id, service, apk_id)
    else:
        print("No data.")

def process_receivers(analysis_id, apk_id, receivers):
    receivers_cnt = len(receivers)
    print(f"\nReceivers ({receivers_cnt})")
    if receivers:
        for receiver in receivers:
            #print(f"- {receiver}") # Debugging
            DBRecordInserts.insert_vt_receivers(analysis_id, receiver, apk_id)
    else:
        print("No data.")

def process_androguard_data(analysis_id, andro_data):
    apk_id = DB_ApkRecords.get_apk_id_by_sha256(andro_data.get_sha256())

    process_metadata(analysis_id, andro_data)
    process_permissions(analysis_id, apk_id, andro_data.get_permissions())
    process_activities(analysis_id, apk_id, andro_data.get_activities())
    process_services(analysis_id, apk_id, andro_data.get_services())
    process_receivers(analysis_id, apk_id, andro_data.get_receivers())

def read_hash_data():
    hash_file_path = "input\\Hash-Data.txt"
    hashes = []

    print("\nRead Hash Data...")
    with open(hash_file_path, 'r') as file:
        for line in file:
            hash_value = line.strip()
            if hash_value:
                hashes.append(hash_value)

    records = DB_ApkRecords.get_apk_samples_by_md5_list(hashes)
    if not records:
        print("Error: no records returned from the database .")
        return
    
    print("\nProcessing Hash Data...")
    for index in records:
        response = vt_requests.query_hash(index[1])
        analysis_name = "Hash Data Analysis"
        process_vt_response(response, analysis_name)

def process_apk_sample(record):
    print(f"Android APK ID: {record[0]} Hash: {record[1]}")
    hash_value = record[1]  # hash value
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Processing APK Sample"
    process_vt_response(response, analysis_name)

def run_analysis(iterative_mode=False):
    try:
        apk_records = DB_ApkRecords.get_apk_records_sha256()
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
