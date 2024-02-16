from database import DB_AnalysisRecords, DB_ApkRecords, DBRecordInserts
from utils import app_utils, user_prompts
from permission_analysis import permission_analyzer
from . import vt_androguard, vt_requests

def process_vt_response(response, analysis_name):
    try:
        analysis_id = DB_AnalysisRecords.create_analysis_record(analysis_name)
        print(f"Analysis ID: {analysis_id}")
        andro_data = vt_androguard.androguard_data(response)
        if andro_data:
            process_androguard_data(analysis_id, andro_data)
        else:
            print("No Androguard data returned...")

        vt_data = vt_requests.parse_virustotal_response(response)
        if vt_data:
            apk_id = DB_ApkRecords.get_apk_id_by_sha256(andro_data.get_sha256())
            DBRecordInserts.create_vt_engine_record(analysis_id, apk_id) 

            summary_stat = vt_data["Analysis Result"]["summary_statistics"]
            DBRecordInserts.update_vt_engine_detection(analysis_id, summary_stat)
   
            vendor_data = vt_data["Analysis Result"]["engine_detection"]
            DBRecordInserts.update_vt_engine_records(analysis_id, vendor_data)

            json_filename = "output\\" + andro_data.get_sha256() + "_json_data.txt"
            #vt_utils.save_json_response(vt_data, json_filename)

        DB_AnalysisRecords.update_status_to_completed(analysis_id)
        user_prompts.pause_until_keypress()

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
    print("\nAPK Analysis Report\n" + "=" * 50)
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

def process_androguard_data(analysis_id, andro_data):
    apk_id = DB_ApkRecords.get_apk_id_by_sha256(andro_data.get_sha256())

    process_summary_data(analysis_id, andro_data)
    process_permissions(analysis_id, apk_id, andro_data.get_permissions())
    process_activities(analysis_id, apk_id, andro_data.get_activities())
    process_services(analysis_id, apk_id, andro_data.get_services())
    process_receivers(analysis_id, apk_id, andro_data.get_receivers())

    footer = "=" * 50
    print(f"\n{footer}\n")

def process_apk_sample(record):
    print(f"Android APK ID: {record[0]} SHA-256: {record[1]}")
    hash_value = record[1]  # SHA256 hash value
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Test Run 2/15/2024"
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

def check_unanalyzed_malware_ioc():
    # Part 1: Check for Missing VirusTotal Report URLs
    results = DB_ApkRecords.get_unanalyzed_malware_ioc_threats()
    if results:
        print(f"Unanalyzed threats: {len(results)}\n")
        for i in results:
            print(f"Threat ID: {i[0]} SHA-256: {i[6]}")
            response = vt_requests.query_hash(i[6])
            vt_data = vt_requests.parse_virustotal_response(response)
            if vt_data:
                if vt_data['Report URL']:
                    print(f"\n{vt_data['Report URL']}")
                    DB_ApkRecords.update_malware_ioc_vt_url(i[0], vt_data['Report URL'])
                    user_prompts.pause_until_keypress()

    # Part 2: check if apk_samples are missing records
    malware_iocs = DB_ApkRecords.get_malware_hash_samples()
    if malware_iocs:
        for i in malware_iocs:
            results = DB_ApkRecords.get_apk_sample_record_by_sha256(i[6])
            if not results:
                print(f"Missing Record for {i[0]} SHA-256: {i[6]}")
                response = vt_requests.query_hash(i[6])
                vt_data = vt_requests.parse_virustotal_response(response)
                if vt_data:
                    if not DBRecordInserts.create_apk_sample_record(i[6], vt_data['Size'], vt_data['MD5'], vt_data['SHA1'], vt_data['SHA256']):
                        print("Error: creating apk sample record")
                    else:
                        print("New record created.")
                    user_prompts.pause_until_keypress()
    
    