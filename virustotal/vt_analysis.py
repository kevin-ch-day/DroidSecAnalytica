# vt_analysis.py

from database import db_update_records, db_get_records, db_create_records
from . import vt_androguard, vt_requests, vt_processing

def analyze_hash_data():
    hashes = []
    print("\n[Step 1] Reading Hash Data from File...")

    try:
        with open("input/Hash-Data.txt", 'r') as file:
            for line in file:
                hash_value = line.strip()
                if hash_value:
                    hashes.append(hash_value)
    except FileNotFoundError:
        print("[Error] The specified hash data file was not found. Please check the file path and try again.")
        return
    except Exception as e:
        print(f"[Error] An unexpected error occurred while reading the file: {e}")
        return

    if not hashes:
        print("[Warning] No hashes were found in the file. Please ensure the file contains hash values.")
        return

    print(f"Successfully read {len(hashes)} hash(es).")
    
    print("\n[Step 2] Querying Database for Records...")
    records = db_get_records.get_apk_samples_by_md5(hashes)
    if not records:
        print("[Warning] No matching records found in the database for the provided hashes.")
        return

    print(f"Found {len(records)} record(s) matching the hash(es).")
    
    print("\n[Step 3] Processing Hash Data and Sending Requests...")
    processed_count = 0
    for record in records:
        response = vt_requests.query_hash(record[4])
        analysis_name = "Test Run"
        sample_type = "Hash"
        process_vt_response(response, analysis_name, sample_type)
        processed_count += 1
        print(f"Processed {processed_count}/{len(records)} records.")

    print("\nAll hash data processed successfully.")

def process_vt_response(response, analysis_name, sample_type):
    try:
        analysis_id = db_create_records.create_analysis_record(analysis_name, sample_type)
        print(f"\nAnalysis ID: {analysis_id}")
        
        andro_data = vt_androguard.handle_androguard_response(response)
        if andro_data:
            vt_processing.process_androguard_data(analysis_id, andro_data)
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
            #json_filename = "output\\" + andro_data.get_md5() + "_json_data.txt"
            #vt_utils.save_json_response(vt_data, json_filename)

        db_update_records.update_analysis_status(analysis_id, "Completed")
        #user_prompts.pause_until_keypress()

    except Exception as e:
        print(f"Error processing APK samples: {e}")
