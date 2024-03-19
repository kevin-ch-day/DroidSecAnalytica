# vt_analysis.py

from database import db_update_records, db_get_records, db_insert_records, db_create_records
from static_analysis import record_permissions
from . import vt_androguard, vt_requests

def analyze_hash_data():
    hashes = []

    print("\nRead Hash Data...")
    with open("input\\Hash-Data.txt", 'r') as file:
        for line in file:
            hash_value = line.strip()
            if hash_value:
                hashes.append(hash_value)

    records = db_get_records.get_apk_samples_by_md5(hashes)
    if not records:
        print("[!!] Error: no database records")
        return
    
    print("\nProcessing Hash Data...")
    for index in records:
        response = vt_requests.query_hash(index[4])
        analysis_name = "Test Run"
        sample_type = "Hash"
        process_vt_response(response, analysis_name, sample_type)

def process_vt_response(response, analysis_name, sample_type):
    try:
        analysis_id = db_create_records.create_analysis_record(analysis_name, sample_type)
        print(f"Analysis ID: {analysis_id}")
        
        andro_data = vt_androguard.handle_androguard_response(response)
        if andro_data:
            process_androguard_data(analysis_id, andro_data)
        else:
            print("No Androguard data returned...")

        vt_data = vt_requests.parse_virustotal_response(response)
        if vt_data:
            apk_id = db_get_records.get_apk_id_by_sha256(andro_data.get_sha256())

            print(f"\nCreating Virustotal engine record..")
            db_create_records.create_vt_engine_record(analysis_id, apk_id) 

            summary_stat = vt_data["Analysis Result"]["summary_statistics"]
            #print(f"{summary_stat}\n") # DEBUGGING
            print(f"Adding summary stats.")
            db_update_records.update_vt_engine_detection_metadata(analysis_id, summary_stat)
   
            vendor_data = vt_data["Analysis Result"]["engine_detection"]
            #print(f"{vendor_data}") # DEBUGGING
            print(f"Adding engine results.")
            db_update_records.update_vt_engine_column(analysis_id, vendor_data)

            # Saving json response
            #json_filename = "output\\" + andro_data.get_sha256() + "_json_data.txt"
            #vt_utils.save_json_response(vt_data, json_filename)

        db_update_records.update_status_to_completed(analysis_id)
        #user_prompts.pause_until_keypress()
        print()

    except Exception as e:
        print(f"Error processing APK samples: {e}")

def process_androguard_data(analysis_id, andro_data):
    apk_id = db_get_records.get_apk_id_by_sha256(andro_data.get_sha256())
    print(f"Sample ID: {apk_id}")
    process_metadata(analysis_id, andro_data)
    process_permissions(analysis_id, apk_id, andro_data.get_permissions())  
    process_activities(analysis_id, apk_id, andro_data.get_activities())
    process_services(analysis_id, apk_id, andro_data.get_services())
    process_receivers(analysis_id, apk_id, andro_data.get_receivers())
    process_providers(analysis_id, apk_id, andro_data.get_providers())

def process_metadata(analysis_id, andro_data):    
    # Retrieve data with checks for None values or defaulting to 'Not Available'
    md5 = andro_data.get_md5() or 'Not Available'
    sha1 = andro_data.get_sha1() or 'Not Available'
    sha256 = andro_data.get_sha256() or 'Not Available'
    package_name = andro_data.get_package() or 'Not Available'
    main_activity = andro_data.get_main_activity() or 'Not Available'
    target_sdk = andro_data.get_target_sdk_version() or 'Not Available'
    min_sdk = andro_data.get_min_sdk_version() or 'Not Available'
    
    # Display the retrieved information
    print(f"MD5:                {md5}")
    print(f"SHA1:               {sha1}")
    print(f"SHA256:             {sha256}")
    print(f"Package Name:       {package_name}")
    print(f"Main Activity:      {main_activity}")
    print(f"Minimum SDK Version: {min_sdk}")
    print(f"Target SDK Version: {target_sdk}")
    
    # Insert the record into the database
    try:
        db_update_records.update_analysis_metadata(analysis_id, sha256, package_name, main_activity, min_sdk, target_sdk)
    except Exception as e:
        print(f"\nFailed to update database. Error: {e}")

def process_permissions(analysis_id, apk_id, permissions):
    print(f"\n# Permissions: {len(permissions)}")
    db_update_records.update_analysis_metadata_column(analysis_id, "permissions", len(permissions))
    if permissions:
        for index in permissions:
            record_permissions.save_detected_permission(analysis_id, apk_id, permissions[index])
    else:
        print("No data.")

def process_activities(analysis_id, apk_id, activities):
    print(f"\n# Activities: ({len(activities)})")
    db_update_records.update_analysis_metadata_column(analysis_id, "activities", len(activities))
    if activities:
        for activity in activities:
            #print(f"- {activity}") # Debugging
            db_insert_records.insert_vt_activities(analysis_id, activity, apk_id)
    else:
        print("No data.")

def process_services(analysis_id, apk_id, services):
    print(f"\n# Services: ({len(services)})")
    db_update_records.update_analysis_metadata_column(analysis_id, "services", len(services))
    if services:
        for service in services:
            #print(f"- {service}") # Debugging
            db_insert_records.insert_vt_services(analysis_id, service, apk_id)
    else:
        print("No data.")

def process_receivers(analysis_id, apk_id, receivers):
    print(f"\n# Receivers: ({len(receivers)})")
    db_update_records.update_analysis_metadata_column(analysis_id, "receivers", len(receivers))
    if receivers:
        for receiver in receivers:
            #print(f"- {receiver}") # Debugging
            db_insert_records.insert_vt_receivers(analysis_id, receiver, apk_id)
    else:
        print("No data.")

def process_providers(analysis_id, apk_id, providers):
    print(f"\n# Providers: ({len(providers)})")
    db_update_records.update_analysis_metadata_column(analysis_id, "providers", len(providers))
    if providers:
        for index in providers:
            #print(f"- {provider:}") # Debugging
            db_insert_records.insert_vt_providers(analysis_id, index, apk_id)
    else:
        print("No data.")