# vt_analysis.py

import pandas as pd

from database import db_update_records, db_get_records, db_create_records, db_classification_func, db_util_func
from utils import user_prompts
from reporting import generate_vt_reports as vt_reports
from . import vendor_classifications, vt_androguard, vt_requests, vt_processing, vt_utils

def process_hashes(records):
    print("\n[Step 3] Processing Hash Data...")
    for count, record in enumerate(records, start=1):
        response = vt_requests.query_hash(record[4])  # MD5 hash
        analysis_name = "Test Run"
        sample_type = "Hash"
        save_json = False
        pause_process = False
        process_vt_response(response, analysis_name, sample_type, save_json, pause_process)
        print(f"Processed {count}/{len(records)} records.")
    print("\nAll hash data processed successfully.")

def analyze_hash_data():
    hashes = load_hashes_from_file("input/Hash-Data.txt")
    if hashes is None:
        return  # Error message is handled within the function

    if not hashes:
        print("[Warning] No hashes were found in the file.")
        return

    records = query_database_for_records(hashes)
    if not records:
        return  # Error or warning message is handled within the function

    process_hashes(records)

def load_hashes_from_file(filepath):
    print("\n[Step 1] Reading Hash Data from File...")
    try:
        with open(filepath, 'r') as file:
            hashes = [line.strip() for line in file if line.strip()]
        print(f"Successfully read {len(hashes)} hash(es).")
        return hashes
    except FileNotFoundError:
        print("[Error] The specified hash data file was not found.")
    except Exception as e:
        print(f"[Error] An unexpected error occurred while reading the file: {e}")
    return None

def query_database_for_records(hashes):
    print("\n[Step 2] Querying Database for Records...")
    records = db_get_records.get_apk_samples_by_md5(hashes)
    if not records:
        print("[Warning] No matching records found in the database.")
        return []
    else:
        print(f"Found {len(records)} record(s) matching the hash(es).")
        return records

def process_vt_response(response, analysis_name, sample_type, save_json, pause_process):
    print("\n[Processing] VirusTotal Response...")
    try:
        analysis_id = create_analysis_record(analysis_name, sample_type)
        
        andro_data = process_androguard_response(response, analysis_id)
        vt_data = process_virustotal_data(response, analysis_id, andro_data, save_json)
        
        if andro_data:
            classify_and_update_malware(analysis_id, andro_data)
            
        #generate_vt_report_if_applicable(andro_data, vt_data)
        
        finalize_analysis(analysis_id, pause_process)
    except Exception as e:
        print(f"[Error] Failed to process APK samples: {e}")

def process_androguard_response(response, analysis_id):
    andro_data = vt_androguard.handle_androguard_response(response)
    if andro_data:
        vt_processing.process_androguard_data(analysis_id, andro_data)
        print("Processed Androguard data.")
    else:
        print("No Androguard data found in response.")
    return andro_data

def process_virustotal_data(response, analysis_id, andro_data, save_json):
    vt_data = parse_virustotal_response(response)
    if vt_data:
        process_vt_data(analysis_id, andro_data, vt_data, save_json)
        print("Processed VirusTotal data.")
    else:
        print("No VirusTotal data found in response.")
    return vt_data

def classify_and_update_malware(analysis_id, andro_data):
    try:
        print("\n** Malware classification **")
        results = db_classification_func.get_malware_classification(andro_data.get_sha256())
        if not results:
            print("[Error] No results from database for malware classification.")
            return
        
        df = pd.DataFrame(results, columns=[
            'APK ID', 'Name', 'Family',
            'Virustotal', 'AhnLab_V3', 'Alibaba',
            'Ikarus', 'Kaspersky', 'Microsoft',
            'Tencent', 'ZoneAlarm'])
        
        if df.empty:
            print("[Error] Dataframe for malware classification is empty.")
            return
        
        analysis_results = vendor_classifications.analyze_classifications(df)
        if not analysis_results:
            print("No analysis results to process for malware classification.")
            return
        
        for apk_id, vt_engine_data in analysis_results.items():
            new_label = vendor_classifications.data_classification(vt_engine_data)
            print(f"Generated Classification: {new_label}")
            db_classification_func.update_analysis_classification(analysis_id, new_label)
    
    except Exception as e:
        print(f"[Error] Malware classification failed: {e}")

def generate_vt_report_if_applicable(andro_data, vt_data):
    if vt_data and andro_data:
        try:
            print("\n** Generating Virustotal.com Report **")
            vt_reports.generate_report(andro_data, vt_data)
            print("VirusTotal analysis report generated successfully.")
        except Exception as e:
            print(f"[Error] Failed to generate VirusTotal analysis report: {e}")

def create_analysis_record(analysis_name, sample_type):
    analysis_id = db_create_records.create_analysis_record(analysis_name, sample_type)
    print(f"Analysis ID: {analysis_id}")
    return analysis_id

def process_vt_data(analysis_id, andro_data, vt_data, save_json):
    apk_id = get_and_update_apk_record(andro_data, vt_data)

    # Create a record for VirusTotal engine detections
    print("\nCreating engine detected record.")
    db_create_records.create_vt_engine_record(analysis_id, apk_id)
    update_summary_and_detection_stats(analysis_id, vt_data)

    if save_json:
        save_vt_json_response(andro_data, vt_data)

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
    print("Added summary stats results.")

    vendor_data = vt_data["Analysis Result"]["engine_detection"]
    db_update_records.update_vt_engine_column(analysis_id, vendor_data)
    print("Added engine detection results.")

def save_vt_json_response(andro_data, vt_data):
    # Save the VirusTotal JSON response to a file.
    json_filename = f"output/{andro_data.get_md5()}_json_data.txt"
    vt_utils.save_json_response(vt_data, json_filename)
    print(f"Saved JSON response to {json_filename}")


def parse_virustotal_response(response):
    print("\nParsing VirusTotal response...")
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

        print("VirusTotal response parsed successfully.")
        return report
    except Exception as e:
        print(f"Error parsing VirusTotal response: {e}")
        return None

def parse_engine_detection(attributes):
    detailed_breakdown = attributes.get('last_analysis_results', {})
    return [[engine, data.get('result', 'N/A')] for engine, data in sorted(detailed_breakdown.items())]

def finalize_analysis(analysis_id, pause_process):
    db_update_records.update_analysis_status(analysis_id, "Completed")
    print(f"\nAnalysis # {analysis_id} completed.")
    if pause_process:
        print("Press any key to continue...")
        user_prompts.pause_until_keypress()

def create_vt_report(andro_data, vt_data):
    # Generates and saves the VirusTotal analysis report.
    if vt_data and andro_data:
        try:
            vt_reports.generate_report(andro_data, vt_data)
            print("VirusTotal analysis report generated successfully.")
        except Exception as e:
            print(f"Error generating VirusTotal analysis report: {e}")
    else:
        print("No VirusTotal data available to generate the report.")