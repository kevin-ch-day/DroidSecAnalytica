# vt_analysis.py

# Python Libraries
import pandas as pd
import sys

# Custom Libraries
from db_operations import db_update_records, db_get_records, db_create_records, db_util_func, db_insert_records
from utils import utils_func, hash_preload
from reporting import generate_vt_reports as vt_reports
from . import vendor_classifications, vt_androguard, vt_requests, vt_processing, vt_utils

def test_hash_virustotal():
    hash = "fdb64ef888a0f1fe8c305453803b3ee7029dc0d4f42c70af34b6d4aaee4359b4"
    response = vt_requests.query_virustotal(hash, "hash")
    process_vt_response(response, "hash")

def load_hashes_from_source():
    print("\n" + "="*40)
    print("          *** HASH LOADING MENU ***          ")
    print("="*40)
    print("\n [1] Load from file")
    print(" [2] Load from database")
    print("="*40)
    
    choice_prompt = input("\nEnter your choice (1 or 2): ")    
    try:
        user_choice = int(choice_prompt)
    except ValueError:
        print("[ERROR] Invalid input. Please enter 1 or 2.")
        return load_hashes_from_source()

    # load from file
    if user_choice == 1:
        FILE_PATH = "input\\Hash-Data-Small.txt"
        hashes = utils_func.read_hash_file_data(FILE_PATH)
    
    # load from database
    elif user_choice == 2:
        hashes = hash_preload.get_all_hashes_list()
    
    else:
        print("[ERROR] Invalid option chosen. Exiting...")
        return None

    return hashes

def analyze_database_hash_data():
    hash_results = hash_preload.get_unanalyzed_hashes()
    if hash_results is None:
        print("[Error] Failed to load hashes from source.")
        return
    elif not hash_results:
        print("[Warning] No hashes were found.")
        return
    
    for count, index in enumerate(hash_results, start=1):
        response = vt_requests.query_virustotal(index, "hash")
        process_vt_response(response, "hash")
        print(f"\nProcessed {count} of {len(hash_results)} records.")
        print(f"{'-' * 60}")
        
    print("\nAll hash data processed successfully.")

def analyze_hash_data():
    # Step 1: Load the hashes from the file or source
    hashes = load_hashes_from_source()

    # Handle errors or empty hash file early
    if hashes is None:
        print("[Error] Failed to load hashes from source.")
        return
    elif not hashes:
        print("[Warning] No hashes were found.")
        return

    # # Step 2: Query the database for records matching the hashes
    # if not hashes:
    #     records = db_get_records.get_all_sample_md5_to_analyze()
    # else:
    #     records = db_get_records.get_apk_samples_by_md5(hashes)
    
    # # Handle no matching records in the database
    # if not records:
    #     print("[Warning] No matching records found in the database.")
    #     return
    # else:
    #     print(f"Found {len(records)} record(s) matching the hash(es).")

    # Step 3: Process the hasheshandle_androguard_response
    for count, index in enumerate(hashes, start=1):
        response = vt_requests.query_virustotal(index, "hash")
        process_vt_response(response, "hash")
        print(f"\nProcessed {count} of {len(hashes)} records.")
        print(f"{'-' * 60}")
        
    print("\nAll hash data processed successfully.")

def process_vt_response(response, sample_type):
    print("Processing VirusTotal response...")

    # Safely get data from the response
    response_data = response.get('data', {})
    if not response_data:
        print("[Error] No data return...")
        return None

    # Get attributes, androguard data
    data_attributes = response_data.get('attributes', {})
    data_sha256= data_attributes.get('sha256', None)
    data_type_description = data_attributes.get('type_description', None)

    #utils_func.is_valid_sha256()

    db_update_records.update_malware_type_description(data_sha256, data_type_description)

    if "Win32 EXE" == data_type_description:
        print("SAMPLE TYPE DESCRIPTION: Win32 EXE")
        return
    elif "Android" != data_type_description:
        print(f"SAMPLE TYPE DESCRIPTION: {data_type_description}")
        return
    
    try:
        analysis_id = create_analysis_record(sample_type)
        andro_data = vt_androguard.handle_androguard_response(response)
        if andro_data:
            vt_data = process_virustotal_data(response, analysis_id, andro_data) # JSON response from VirusTotal.com
            vt_processing.process_androguard_data(analysis_id, andro_data)
            malware_classification(analysis_id, andro_data)

            # hash_data_ioc table
            if not db_get_records.check_hash_exists(andro_data.get_md5(), andro_data.get_sha1(), andro_data.get_sha256()):
                db_insert_records.insert_hash_data(andro_data.get_md5(), andro_data.get_sha1(), andro_data.get_sha256())

            else:
                db_update_records.update_hash_data_ioc_record(andro_data.get_md5(), andro_data.get_sha1(), andro_data.get_sha256())
                db_update_records.update_analysis_status(analysis_id, "Completed")
   
        else:
            print("No Androguard data found in response.")
            db_update_records.update_analysis_status(analysis_id, "Incompleted")

    except Exception as e:
        error_message = str(e)
        print(f"[Error] {error_message}")

        # Check if it's a database connection error or query failure
        if "Database connection failed" in error_message or "Failed to execute query" in error_message:
            print("Critical database error occurred. Exiting the program...")
            sys.exit(1)
        else:
            print(f"An unexpected error occurred: {error_message}")

def process_virustotal_data(response, analysis_id, andro_data):
    vt_data = parse_virustotal_response(response)    
    if vt_data:
        apk_id = get_and_update_apk_record(andro_data, vt_data)
        db_create_records.create_vt_engine_record(analysis_id, apk_id)
        update_summary_and_detection_stats(analysis_id, vt_data)

    else:
        print("No VirusTotal data found in response.")
    
    return vt_data

def malware_classification(analysis_id, andro_data):
    try:
        results = db_get_records.get_malware_classification(andro_data.get_sha256())
        if not results:
            print("[Error] No results from database for malware classification.")
            exit()
            return
        
        df = pd.DataFrame(results, columns=[
            'APK ID', 'Name', 'Family',
            'Virustotal', 'AhnLab_V3', 'Alibaba', 'Ikarus',
            'Kaspersky', 'Microsoft', 'Tencent', 'ZoneAlarm'])
        
        if df.empty:
            print("\n[Error] Dataframe for malware classification is empty.")
            return
        
        analysis_results = vendor_classifications.analyze_classifications(df)
        if not analysis_results:
            print("No analysis results to process for malware classification.")
            return

        # Iterate over the items in analysis_results
        for result in analysis_results.items(): 
            # Check if the result has two elements before unpacking
            if isinstance(result, tuple) and len(result) == 2:
                apk_id, vt_engine_data = result
                classification = vendor_classifications.data_classification(vt_engine_data)
                
                print(f"\n{'DroidSecAnalytica:':<26}{classification}")
                db_update_records.update_analysis_classification(analysis_id, classification)
            
            else:
                print(f"\n[Error] Unexpected result structure or number of values: {result}")

    except Exception as e:
        print(f"[Error] Malware classification failed: {e}")
        exit(1)

def generate_vt_report_if_applicable(andro_data, vt_data):
    if vt_data and andro_data:
        try:
            print("\n** Generating Virustotal.com Report **")
            vt_reports.generate_report(andro_data, vt_data)
            print("VirusTotal analysis report generated successfully.")
        except Exception as e:
            print(f"[Error] Failed to generate VirusTotal analysis report: {e}")

def create_analysis_record(sample_type):
    analysis_id = db_create_records.create_analysis_record(sample_type)
    print(f"Analysis ID: {analysis_id}")
    return analysis_id

def get_and_update_apk_record(andro_data, vt_data):
    # Retrieve the APK ID using SHA256, update the VirusTotal report URL, sample size, and formatted size in the database.
    apk_id = db_get_records.get_apk_id_by_sha256(andro_data.get_sha256())

    update_if_missing(db_util_func.check_vt_malware_url, db_util_func.update_virustotal_url, apk_id, vt_data["Report URL"], "VirusTotal report URL")
    update_if_missing(db_util_func.check_vt_malware_size, db_util_func.update_sample_size, apk_id, vt_data["Size"], "sample size")
    update_if_missing(db_util_func.check_vt_malware_formatted_size, db_util_func.update_formatted_size_sample, apk_id, vt_data["Formatted Size"], "formatted sample size")

    return apk_id

def update_if_missing(check_func, update_func, apk_id, new_value, data_description):
    # Check if specific data is missing and update it in the database.
    if not check_func(apk_id):
        update_func(apk_id, new_value)
        print(f"Updated {data_description}.")

def update_summary_and_detection_stats(analysis_id, vt_data):
    # Update the database with summary statistics and engine detection results from the VirusTotal data.
    summary_stat = vt_data["Analysis Result"]["summary_statistics"]
    db_update_records.update_vt_engine_detection_metadata(analysis_id, summary_stat)
    #print("Added summary stats results.") # DEBUGGING

    vendor_data = vt_data["Analysis Result"]["engine_detection"]
    db_update_records.update_vt_engine_column(analysis_id, vendor_data)
    #print("Added engine detection results.") # DEBUGGING

def parse_virustotal_response(response):
    try:
        data = response.get('data', {})
        if not data:
            raise ValueError("No 'data' key in response.")
        
        attributes = data.get('attributes', {})
        if not attributes:
            raise ValueError("No valid attributes found in the data.")

        analysis_result = {
            'summary_statistics': {key.capitalize(): value for key, value in attributes.get('last_analysis_stats', {}).items()},
            'engine_detection': parse_engine_detection(attributes)
        }

        report = {
            "Report URL": data['links']['self'],
            "Size": attributes['size'],
            "Formatted Size": vt_utils.format_file_size(attributes['size']),
            "MD5": attributes['md5'],
            "SHA1": attributes['sha1'],
            "SHA256": attributes['sha256'],
            "Last Submission Date": vt_utils.format_timestamp(attributes['last_submission_date']),
            "Last Analysis Date": vt_utils.format_timestamp(attributes['last_analysis_date']),
            "Other Names": sorted(attributes.get('names', [])),
            "Analysis Result": analysis_result
        }

        return report
    
    except Exception as e:
        print(f"Error parsing VirusTotal response: {e}")
        return None

def parse_engine_detection(attributes):
    detailed_breakdown = attributes.get('last_analysis_results', {})
    return [[engine, data.get('result', 'N/A')] for engine, data in sorted(detailed_breakdown.items())]

def create_vt_report(andro_data, vt_data):
    if vt_data and andro_data:
        try:
            vt_reports.generate_report(andro_data, vt_data)
            print("VirusTotal analysis report generated successfully.")
        except Exception as e:
            print(f"Error generating VirusTotal analysis report: {e}")
    else:
        print("No VirusTotal data available to generate the report.")