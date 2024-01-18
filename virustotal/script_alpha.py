# analysis_app.py

import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from utils import data_processing, report_generation
from database  import DBConnectionManager

API_KEY = '848c2f7d2499138423f7416f61b8a3e42d8dd9a429ca9bc6f4f478c590c8eec7'

def query_virustotal(api_key, hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error occurred: {e}")
        return None

def analyze_data(data):
    total_scans = len(data['data']['attributes']['last_analysis_results'])
    malicious_count = sum(1 for result in data['data']['attributes']['last_analysis_results'].values() if result['category'] == 'malicious')
    benign_count = total_scans - malicious_count
    detection_ratio = malicious_count / total_scans if total_scans > 0 else 0.0

    analysis_results = {
        'Total Scans': total_scans,
        'Malicious Count': malicious_count,
        'Benign Count': benign_count,
        'Detection Ratio': detection_ratio,
    }
    return analysis_results

def plot_histogram(data):
    # Plot a histogram of detection results
    df = pd.DataFrame(data)
    plt.figure(figsize=(8, 6))
    sns.histplot(data=df, x='Detection Ratio', bins=20, kde=True)
    plt.xlabel('Detection Ratio')
    plt.ylabel('Frequency')
    plt.title('Distribution of Detection Ratios')
    plt.savefig('detection_ratio_histogram.png')
    plt.close()

def retrieve_hashes_from_virustotal(hash):
    url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={hash}'
    response = requests.get(url)
    data = response.json()
    if response.status_code == 200 and 'positives' in data:
        return {
            'md5': data.get('md5', 'N/A'),
            'sha1': data.get('sha1', 'N/A'),
            'sha256': data.get('sha256', 'N/A')}
    else:
        return {'error': 'No data found or API error'}


def check_matching_hashes(result, md5, sha1, sha256):
    # Check if result is None or empty
    if not result:
        return "No result provided for comparison."

    # Check if result contains an error message
    if 'error' in result:
        return f"Error in hash retrieval: {result['error']}"

    # Comparing returned hashes with stored values
    matched_hashes = []
    if 'md5' in result and result['md5'] == md5:
        matched_hashes.append(f"MD5 matched: {md5}")
    if 'sha1' in result and result['sha1'] == sha1:
        matched_hashes.append(f"SHA1 matched: {sha1}")
    if 'sha256' in result and result['sha256'] == sha256:
        matched_hashes.append(f"SHA256 matched: {sha256}")
    
    # Constructing the return message based on matched hashes
    if matched_hashes:
        return "Matched Hash(es): " + ", ".join(matched_hashes)
    else:
        return "No matching hashes found among returned results."

def function_alpha():
    conn = DBConnectionManager.connect_to_database()
    if conn:
        cursor = conn.cursor()
        select_sql = "SELECT * FROM android_malware_hashes"
        cursor.execute(select_sql)
        records = cursor.fetchall()
        
        for record in records:
            md5 = record[3]
            sha1 = record[4]
            sha256 = record[5]
            valid_hash = md5 or sha1 or sha256
            
            # Determine the type of hash being used
            hash_type = "MD5" if md5 else ("SHA1" if sha1 else "SHA256")
            print("Analyzing record")
            print(f"Hash record Type:{hash_type} IOC: {valid_hash}")
            response = query_virustotal(API_KEY, valid_hash)
            if response:
                data_processing.write_json_to_file(f'output/raw_virustotal_data_{valid_hash}.json', response)
                analysis_results = data_processing.extract_and_analyze_data(response)
                analysis_df = pd.DataFrame([analysis_results])

                # report_generation.generate_report(
                #     analysis_df, 
                #     f'report_{valid_hash}.pdf',
                #     f"MD5: {md5}",
                #     f"SHA1: {sha1}",
                #     f"SHA256: {sha256}",
                #     f"Valid Hash: {valid_hash}")

                print(f"Analysis completed for Valid Hash: {valid_hash}")
                print("Comprehensive report generated and data saved to the database.")
            else:
                print(f"Failed to analyze Valid Hash: {valid_hash}")
        
        cursor.close()
        conn.close()

def main():
    conn = DBConnectionManager.connect_to_database()
    if conn:
        cursor = conn.cursor()
        select_sql = "SELECT * FROM android_malware_hashes"
        cursor.execute(select_sql)
        records = cursor.fetchall()
        
        for record in records:
            md5 = record[3]
            sha1 = record[4]
            sha256 = record[5]
            valid_hash = md5 or sha1 or sha256
            
            # Determine the type of hash being used
            hash_type = "MD5" if md5 else ("SHA1" if sha1 else "SHA256")
            print("Analyzing record")
            print(f"Hash record Type:{hash_type} IOC: {valid_hash}")
            result = retrieve_hashes_from_virustotal(valid_hash)
            check_matching_hashes(result)
            exit()
        
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()
