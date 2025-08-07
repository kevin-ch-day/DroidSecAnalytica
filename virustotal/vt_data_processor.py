# vt_data_processor.py

import sys

from database import db_update_records, db_get_records, db_create_records, db_util_func, db_malware_classification
from . import vt_androguard, vt_processing, vt_utils, vt_malware_classification

def create_analysis_record(sample_type):
    analysis_id = db_create_records.create_analysis_record(sample_type)
    print(f"\nCreating new analysis ID: {analysis_id}")
    return analysis_id

def process_vt_response(response, sample_type):

    # Check if 'error' exists in the response
    if 'error' in response:
        error_code = response['error'].get('code', 'UnknownError')
        error_message = response['error'].get('message', 'No error message provided.')

        print(f"\n[!!] VirusTotal API Error")
        print(f"Error [{error_code}]: {error_message}")
        return

    else:
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

        print(f"Malware type description: {data_type_description}")
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
                vt_data = parse_virustotal_response(response)
                if vt_data:
                    apk_id = get_and_update_apk_record(andro_data, vt_data)
                    
                    print("Recording virustotal AV engine results.")
                    db_malware_classification.create_vt_engine_record(analysis_id, apk_id)
                    
                    # Update the database with summary statistics and engine detection results from the VirusTotal data.
                    summary_stat = vt_data["Analysis Result"]["summary_statistics"]
                    db_malware_classification.update_vt_engine_detection_metadata(analysis_id, summary_stat)
                    
                    vendor_data = vt_data["Analysis Result"]["engine_detection"]
                    db_malware_classification.update_vt_engine_column(analysis_id, vendor_data)
                    
                    vt_malware_classification.malware_classification(analysis_id, andro_data)

                    vt_processing.process_androguard_data(analysis_id, andro_data)
                    db_update_records.update_analysis_status(analysis_id, "Completed")
                    
                else:
                    print("No VirusTotal data found in response.")   

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
