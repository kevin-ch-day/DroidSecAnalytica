# analysis_app.py

import requests
import json
import time
import datetime

from database import DBConnectionManager
from database import DBUtils
from utils import app_utils

API_KEY = '9665abbb72d64b0eae5b6fcc13db35c6139069fb1f9ae9db0824ba256e354a01'

def json_string_to_dict(json_string):
    try:
        json_data = json.loads(json_string)
        return json_data
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return None

def fetch_virustotal_report(file_hash):
    report_url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={file_hash}'

    try:
        response = requests.get(report_url)

        if response.status_code == 200:
            try:
                json_data = response.json()
            except json.JSONDecodeError:
                return {'error': 'Invalid JSON response from VirusTotal'}

            # Save response to a file
            try:
                with open(f'{file_hash}_virustotal_report.json', 'w') as file:
                    json.dump(json_data, file, indent=4)
            except IOError as e:
                return {'error': f'Error writing file: {e}'}
            
            return json_data

        elif response.status_code == 403:
            return {'error': 'Access denied, check your API key'}
        elif response.status_code == 404:
            return {'error': 'No report found for the provided hash'}
        else:
            return {'error': f'Request failed with status code {response.status_code}'}

    except requests.RequestException as request_error:
        return {'error': f'HTTP request error: {request_error}'}

def get_virustotal_hash_values(hash):
    url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={hash}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            try:
                data = response.json()
                print("MD5:\t", data.get('md5', 'N/A'))
                print("SHA1:\t", data.get('sha1', 'N/A'))
                print("SHA256:\t", data.get('sha256', 'N/A'))

                if 'positives' in data:
                    return {
                        'md5': data.get('md5', 'N/A'),
                        'sha1': data.get('sha1', 'N/A'),
                        'sha256': data.get('sha256', 'N/A')}
                else:
                    return {'error': 'No positives found in data'}
                
            except json.JSONDecodeError:
                return {'error': 'Invalid JSON response'}
        else:
            return {'error': f'Request failed with status code {response.status_code}'}
    except requests.RequestException as e:
        return {'error': f'HTTP request error: {e}'}

def check_matching_hashes(result, md5, sha1, sha256):
    """
    Check if the retrieved hashes match the provided hashes.
    """
    if not result:
        return "No result provided for comparison."
    if 'error' in result:
        return f"Error in hash retrieval: {result['error']}"

    matched_hashes = []
    if 'md5' in result and result['md5'] == md5:
        matched_hashes.append(f"MD5 matched: {md5}")
    if 'sha1' in result and result['sha1'] == sha1:
        matched_hashes.append(f"SHA1 matched: {sha1}")
    if 'sha256' in result and result['sha256'] == sha256:
        matched_hashes.append(f"SHA256 matched: {sha256}")
    
    if matched_hashes:
        return "\nMatched Hash(es): " + ", ".join(matched_hashes)
    else:
        return "\nNo matching hashes found among returned results."

def update_database_hash_records(record_id, hash_values):
    """
    Update the database record with matched hash values.
    """
    try:
        conn = DBConnectionManager.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                update_fields = []
                update_values = []
                for hash_type, value in hash_values.items():
                    if value:
                        update_fields.append(f"{hash_type} = %s")
                        update_values.append(value)
                
                if update_fields:
                    update_sql = f"UPDATE android_malware_hashes SET {', '.join(update_fields)} WHERE id = %s"
                    cursor.execute(update_sql, update_values + [record_id])
                    if cursor.rowcount > 0:
                        print(f"Database record updated.")
                    else:
                        print(f"Database record not updated. Exiting...")
                    
                    conn.commit()
    except Exception as e:
        print(f"Error updating record ID {record_id}: {e}")
    finally:
        conn.close()

def process_record(record):
    """
    Process a database record, check for matching hashes, and update the record if necessary.
    """
    md5 = record[3]
    sha1 = record[4]
    sha256 = record[5]
    valid_hash = md5 or sha1 or sha256

    hash_values = get_virustotal_hash_values(valid_hash)
    
    if "No positives found in data" in hash_values:
        print(f"Error in hash retrieval: {hash_values['error']}")
        DBConnectionManager.update_records_no_virustotal_match(record[0])
        return
    
    check_result = check_matching_hashes(hash_values, md5, sha1, sha256)
    if "Matched" in check_result:
        update_values = {
            'md5': hash_values.get('md5'),
            'sha1': hash_values.get('sha1'),
            'sha256': hash_values.get('sha256')
        }
        update_database_hash_records(record[0], update_values)

def display_estimated_completion_time(total_batches, batch_interval):
    # Calculate and display the estimated completion time
    time_now = datetime.datetime.now()
    time_next_batch = time_now + datetime.timedelta(seconds=batch_interval * total_batches)
    time_next_batch_ct = time_next_batch - datetime.timedelta(hours=5)  # Convert to CT

    # Calculate remaining time in hours and minutes
    remaining_time = (time_next_batch_ct - datetime.datetime.now()).total_seconds()
    hours, seconds = divmod(remaining_time, 3600)
    minutes = (seconds % 3600) // 60
    formatted_time = time_next_batch_ct.strftime('%I:%M:%S %p CT %m-%d-%Y')
    
    # Create a user-friendly message
    message = "Estimated Completion Time: "
    message += f"{formatted_time}\n"
    
    if hours >= 1:
        message += f"{int(hours)} {'hour' if int(hours) == 1 else 'hours'}"
        if minutes >= 1:
            message += f" and {int(minutes)} {'minute' if int(minutes) == 1 else 'minutes'}"
        message += " remaining"
    elif minutes >= 1:
        message += f"{int(minutes)} {'minute' if int(minutes) == 1 else 'minutes'} remaining"

    # Print the message
    print(f"{'=' * 54}")
    print(message)
    print(f"{'=' * 54}\n")

def check_database_for_missing_hashes():
    total_records = DBUtils.get_total_hash_records()
    num_records = DBUtils.get_total_records_to_process()
    if num_records == 0:
        print("All records have data.\n")
    else:
        print(f"Records to process: {num_records}\n")
    
    iteration_count = 0
    batch_size = 4
    batch_interval = 240  # 4 minutes in seconds
    first_iteration = True
    total_batches = (num_records + batch_size - 1) // batch_size

    for i in range(0, len(total_records), batch_size):
        batch_records = total_records[i:i+batch_size]
        for record in batch_records:

            # Already has hash data
            if all(record[3:6]):
                continue

            # Skip this; no virustotal data from previous scan
            elif record[9]:
                continue

            if first_iteration:
                print(f"ID: {record[0]} {record[1]}")
                first_iteration = False
            else:
                print(f"\nID: {record[0]} {record[1]}")

            process_record(record)
            iteration_count += 1

            if iteration_count == 4:
                print("\nWaiting for the next batch...")
                display_estimated_completion_time(total_batches, batch_interval)
                app_utils.wait_for_next_batch(batch_interval)
                iteration_count = 0 # reset

def main():
    hash = '9fa1e4b615d69f04da261267331a202b'
    result = fetch_virustotal_report(hash)
    d = json_string_to_dict(result)
    if d is not None:
        for k, v in d.items():
            print(f"{k}")
            print(f"{v}")

if __name__ == "__main__":
    main()

