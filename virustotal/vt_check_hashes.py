import os
from database import DB_ApkRecords, DBRecordInserts
from utils import user_prompts
from . import vt_requests

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

def read_hash_data_alpha():
    hash_file_path = "input\\SHA256-Hashes.txt"
    result_file_path = "output\\hash-data-results.txt"
    hashes = read_and_deduplicate_hashes(hash_file_path)
    matching_records, non_matching_hashes = DB_ApkRecords.hash_query_alpha(hashes)
    with open(result_file_path, 'w') as file:
        if matching_records:
            file.write("Matching Records:\n")
            for record in matching_records:
                file.write(format_matching_record(record) + "\n\n")
                
        if non_matching_hashes:
            file.write("\nNon-Matching Hashes:\n")
            for hash_str in non_matching_hashes:
                file.write(f"{hash_str}\n")

def read_and_deduplicate_hashes(file_path):
    """Read hashes from a file and remove duplicates."""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(file_path, 'r') as file:
        unique_hashes = set(file.read().splitlines())
    return unique_hashes

def format_matching_record(record):
    labels = ["ID", "MD5", "SHA-256", "Source", "Name 1", "Name 2", "VirusTotal", "Date"]
    if len(record) > 7:
        record = record[:7] + (f"{record[7]} {record[8]}",)
    formatted_output = "\n".join(f"{label}: {value}" for label, value in zip(labels, record))
    return formatted_output
