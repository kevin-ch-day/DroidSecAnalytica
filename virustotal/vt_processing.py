# vt_processing.py

from database import db_update_records, db_get_records, db_insert_records
from static_analysis import record_permissions

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
    md5 = andro_data.get_md5() or 'Not Available'
    sha1 = andro_data.get_sha1() or 'Not Available'
    sha256 = andro_data.get_sha256() or 'Not Available'
    package_name = andro_data.get_package() or 'Not Available'
    main_activity = andro_data.get_main_activity() or 'Not Available'
    target_sdk = andro_data.get_target_sdk_version() or 'Not Available'
    min_sdk = andro_data.get_min_sdk_version() or 'Not Available'
    
    # Display the retrieved information
    print(f"\nMD5:                {md5}")
    print(f"SHA1:               {sha1}")
    print(f"SHA256:             {sha256}")
    print(f"Package Name:       {package_name}")
    print(f"Main Activity:      {main_activity}")
    print(f"Minimum SDK: {min_sdk}")
    print(f"Target SDK: {target_sdk}")
    
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

def process_activities(analysis_id, apk_id, activities):
    print(f"\n# Activities: {len(activities)}")
    db_update_records.update_analysis_metadata_column(analysis_id, "activities", len(activities))
    if activities:
        for activity in activities:
            #print(f"- {activity}") # Debugging
            db_insert_records.insert_vt_activities(analysis_id, activity, apk_id)

def process_services(analysis_id, apk_id, services):
    print(f"\n# Services: {len(services)}")
    db_update_records.update_analysis_metadata_column(analysis_id, "services", len(services))
    if services:
        for service in services:
            #print(f"- {service}") # Debugging
            db_insert_records.insert_vt_services(analysis_id, service, apk_id)

def process_receivers(analysis_id, apk_id, receivers):
    print(f"\n# Receivers: {len(receivers)}")
    db_update_records.update_analysis_metadata_column(analysis_id, "receivers", len(receivers))
    if receivers:
        for receiver in receivers:
            #print(f"- {receiver}") # Debugging
            db_insert_records.insert_vt_receivers(analysis_id, receiver, apk_id)

def process_providers(analysis_id, apk_id, providers):
    print(f"\n# Providers: {len(providers)}")
    db_update_records.update_analysis_metadata_column(analysis_id, "providers", len(providers))
    if providers:
        for index in providers:
            #print(f"- {provider:}") # Debugging
            db_insert_records.insert_vt_providers(analysis_id, index, apk_id)