# vt_database_analysis.py

from database import DBFunctions
from virustotal import vt_requests, vt_response, vt_utils
from utils import user_prompts

def test_virustotal_request():
    hash = "64ebe9b975de022b888f17db429af3a93d3db95db5af274e3eefd3ca7f24e350"
    response = vt_requests.query_hash(hash)
    print(response)

def print_apk_record(record):
    if record[7]:
        classification = "Malware"
    elif record[8]:
        classification = "Application"
    else:
        classification = "Unknown"

    print(f"\nSample ID: {record[0]} [{classification}]")
    print(f"Name: {record[1]}")
    print(f"MD5: {record[3]}")
    print(f"SHA1: {record[4]}")
    print(f"SHA256: {record[5]}")
    print(f"Source: {record[6]}\n")

def has_missing_data(record):
    md5 = record[3]
    sha1 = record[4]
    sha256 = record[5]

    if md5 is None or sha1 is None or sha256 is None:
        return True
    else:
        return False

def update_apk_record(record, data):
    # Update the record with missing data
    md5 = data.get('MD5')
    sha1 = data.get('SHA1')
    sha256 = data.get('SHA256')
    DBFunctions.update_apk_record(record[0], md5, sha1, sha256)

def process_apk_samples(apk_sample_records):
    print("\nProcessing APK Samples")
    try:
        for record in apk_sample_records:
            print_apk_record(record)

            if has_missing_data(record):
                response = vt_requests.query_hash(record[1])

                # Save JSON response
                # output = f"output/{record[1]}.json"
                # vt_utils.save_json_response(response, output)

                data = vt_response.parse_virustotal_response(response)

                print(f"\nSize: {data['Size']}")
                print(f"Size [Formatted]: {data['Formatted Size']}")
                print(f"MD5: {data['MD5']}")
                print(f"SHA1: {data['SHA1']}")
                print(f"SHA256: {data['SHA256']}\n")

                # Update the record with missing data from VirusTotal
                update_apk_record(record, data)
                user_prompts.pause_until_keypress()

    except Exception as e:
        print(f"Error processing APK samples: {e}")

def run_analysis():
    try:
        apk_sample_records = DBFunctions.get_apk_samples()
        if not apk_sample_records:
            print("No APK samples found in the database.")
            return

        process_apk_samples(apk_sample_records)

    except Exception as e:
        print(f"Error running the analysis: {e}")
