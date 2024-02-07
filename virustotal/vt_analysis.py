from . import vt_response, vt_androguard

from database import DBFunct_ApkRecords, DBFunct_AnalysisRecords, DBFunct_Perm
from virustotal import vt_requests, vt_analysis
from utils import user_prompts, app_utils

def auto_vt_data_processing(response, analysis_name):
    analysis_id = DBFunct_AnalysisRecords.create_analysis_record(analysis_name)
    vt_data = vt_response.parse_virustotal_response(response)

    andro_data = vt_androguard.androguard_data(response)
    if andro_data:
        permissions = andro_data.get_permissions()
        for i in permissions:
            permission_record = DBFunct_Perm.get_permission_record_by_name(i.name)
            if permission_record:
                id = permission_record[0]
                print(f"Record ID: {id} {i.name}")
                DBFunct_Perm.check_standard_permission_record(id, i.name, i.short_desc, i.long_desc, i.permission_type)

            if not permission_record:
                unknown_permission_record = DBFunct_Perm.get_unknown_permission_record_by_id(i.name)
                id = unknown_permission_record[0]
                print(f"Record ID: {id} {i.name}")
                DBFunct_Perm.check_unknown_permission_record(id, i.name, i.short_desc, i.long_desc, i.permission_type)

    else:
        print("No Androguard data returned...")

def run_analysis(iterative_mode=False):
    try:
        apk_records = DBFunct_ApkRecords.get_apk_records_sha256()
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
    
def process_apk_sample(record):
    print(f"ID: {record[0]} SHA-256: {record[1]}")
    hash_value = record[1]  # SHA256 hash
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Test Run #1 2/7/2024"
    vt_analysis.auto_vt_data_processing(response, analysis_name)


def user_vt_data_processing(response):
    data = vt_response.parse_virustotal_response(response)
    print("\nVirusTotal.com Response:")
    print(data)
    
    andro_data = vt_androguard.androguard_data(response)
    if andro_data:
        print("\nPermissions:")
        permissions = andro_data.get_permissions()
        for i in permissions:
            print(i)