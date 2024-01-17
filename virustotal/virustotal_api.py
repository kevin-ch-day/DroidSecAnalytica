import requests
import os
import time
import logging
import json
import pandas as pd
import matplotlib.pyplot as plt
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

API_KEY = '848c2f7d2499138423f7416f61b8a3e42d8dd9a429ca9bc6f4f478c590c8eec7'
HEADERS = {'x-apikey': API_KEY}
MAX_RETRIES = 10
SLEEP_DURATION = 15
OUTPUT_DIR = 'output'

def upload_apk_file(file_path):
    logging.info("Uploading APK file for analysis...")
    url = 'https://www.virustotal.com/api/v3/files'
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(url, headers=HEADERS, files=files)
        response.raise_for_status()
        return response.json()
    except HTTPError as e:
        logging.error(f"HTTP Error occurred: {e.response.status_code} - {e.response.reason}")
    except (ConnectionError, Timeout) as e:
        logging.error(f"Network error: {e}")
    except RequestException as e:
        logging.error(f"Error occurred during file upload: {e}")
    return None

def retrieve_analysis_report(analysis_id):
    logging.info(f"Retrieving analysis report for ID: {analysis_id}...")
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    attempts = 0

    while attempts < MAX_RETRIES:
        try:
            response = requests.get(url, headers=HEADERS)
            response.raise_for_status()
            result = response.json()
            if result['data']['attributes']['status'] == 'completed':
                return result
            logging.info("Analysis still in progress. Waiting...")
            time.sleep(SLEEP_DURATION)
        except HTTPError as e:
            logging.error(f"HTTP Error occurred: {e.response.status_code} - {e.response.reason}")
            return None
        except (ConnectionError, Timeout) as e:
            logging.error(f"Network error: {e}")
        except RequestException as e:
            logging.error(f"Error occurred while retrieving report: {e}")
        finally:
            attempts += 1
            if attempts == MAX_RETRIES:
                logging.error("Max retries reached. Exiting.")

    logging.error("Failed to retrieve the report after several attempts.")
    return None

def generate_data_frame(processed_data):
    df = pd.DataFrame.from_dict(processed_data['vendor_analysis'], orient='index')
    return df

def plot_detection_ratio(processed_data):
    dr = processed_data['detection_ratio']
    labels = ['Malicious', 'Non-malicious']
    sizes = [dr['malicious'], dr['total_vendors'] - dr['malicious']]

    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title("Detection Ratio")
    plt.show()

def process_report_data(report):
    processed_data = {}

    if 'data' in report and 'attributes' in report['data']:
        attributes = report['data']['attributes']

        # Detection ratio
        processed_data['detection_ratio'] = {
            'malicious': attributes.get('stats', {}).get('malicious', 0),
            'total_vendors': attributes.get('stats', {}).get('total', 0)
        }

        # Detailed vendor analysis
        detailed_vendor_analysis = {}
        if 'results' in attributes:
            for vendor, result in attributes['results'].items():
                vendor_info = {
                    'Category': result.get('category', 'Unknown'),
                    'Engine Name': result.get('engine_name', 'N/A'),
                    'Engine Version': result.get('engine_version', 'N/A'),
                    'Result': result.get('result', 'N/A'),
                    'Method': result.get('method', 'N/A'),
                    'Engine Update': result.get('engine_update', 'N/A')
                }
                detailed_vendor_analysis[vendor] = vendor_info
        processed_data['vendor_analysis'] = detailed_vendor_analysis

        # Additional data points
        processed_data['additional_info'] = {
            'file_type': attributes.get('type', 'N/A'),
            'last_analysis_date': attributes.get('last_analysis_date', 'N/A'),
            'community_score': attributes.get('reputation', 'N/A')
        }

        # Behavior analysis (if available)
        behavior_analysis = attributes.get('behavior', {})
        processed_data['behavior_analysis'] = behavior_analysis

    return processed_data

def get_vendor_data(report):
    vendor_list = []
    if 'data' in report and 'attributes' in report['data']:
        attributes = report['data']['attributes']
        if 'results' in attributes:
            vendor_list = sorted(attributes['results'].keys())
    return vendor_list

def save_vendor_names(data):
    file_path = "output/virustotal_vendor_names.txt"
    with open(file_path, 'w') as file:
        for name in data:
            file.write(name + '\n')

    logging.info(f"Vendor names saved to {file_path}")

def get_vendor_results(report):
    vendor_results = {}
    if 'data' in report and 'attributes' in report['data']:
        attributes = report['data']['attributes']
        if 'results' in attributes:
            for vendor, result in attributes['results'].items():
                vendor_results[vendor] = result.get('result', 'N/A')
    return vendor_results

def write_vendor_results_to_file(data):
    file_path = "output/virustotal_vendor_results.txt"
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, 'w') as file:
        for vendor, result in data.items():
            file.write(f"{vendor}: {result}\n")

    logging.info(f"Vendor results saved to {file_path}")

def save_report_to_file(processed_data, file_path):
    with open(file_path, 'w') as file:
        file.write("VirusTotal Analysis Report\n")
        file.write("==========================\n\n")

        # Write detection ratio
        dr = processed_data['detection_ratio']
        file.write(f"Detection Ratio: {dr['malicious']} / {dr['total_vendors']}\n\n")

        # Ensure there's no division by zero
        total_vendors = dr['total_vendors']
        if total_vendors > 0:
            malicious_percentage = dr['malicious'] / total_vendors * 100
            file.write(f"Percentage of Vendors Detected as Malicious: {malicious_percentage:.2f}%\n\n")
        else:
            file.write("Percentage of Vendors Detected as Malicious: N/A (No vendor data available)\n\n")

        # Write detailed vendor analysis
        file.write("Detailed Vendor Analysis:\n")
        for vendor, details in processed_data['vendor_analysis'].items():
            file.write(f"- {vendor} Analysis:\n")
            for key, value in details.items():
                file.write(f"  - {key}: {value}\n")
            file.write("\n")

        # Writing additional information
        file.write("Additional Information:\n")
        for key, value in processed_data['additional_info'].items():
            file.write(f"  - {key}: {value}\n")
        file.write("\n")

        # Behavior Analysis (if any)
        if processed_data['behavior_analysis']:
            file.write("Behavior Analysis:\n")
            # Process and write behavior analysis details. This is a placeholder, adjust according to your data structure
            for key, value in processed_data['behavior_analysis'].items():
                file.write(f"  - {key}: {value}\n")
            file.write("\n")

        file.write("\nEnd of Report\n")

    logging.info(f"Report saved to {file_path}")

def virustotal_scan(apk_path):
    if not os.path.exists(apk_path):
        logging.error(f"APK file does not exist: {apk_path}")
        return

    response = upload_apk_file(apk_path)
    if response and 'data' in response and 'id' in response['data']:
        analysis_id = response['data']['id']
        logging.info(f"APK file uploaded successfully. Analysis ID: {analysis_id}")
        
        report = retrieve_analysis_report(analysis_id)
        if report:
            logging.info("Processing generated report.")
            
            processed_data = process_report_data(report)
            if processed_data:
                save_report_to_file(processed_data, os.path.join(OUTPUT_DIR, 'virustotal_report.txt'))
                
                #vendor_names = get_vendor_data(report)
                #save_vendor_names(vendor_names)

                vendor_results = get_vendor_results(report)
                write_vendor_results_to_file(vendor_results)
        else:
            logging.error("Failed to obtain a complete analysis report.")
    else:
        logging.error("Failed to upload APK file for analysis.")

def fetch_virustotal_report(file_hash):
    """
    Fetches the VirusTotal report for a given file hash and saves the response to a file.
    """
    api_key = 'your_api_key_here'
    report_url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={file_hash}'

    try:
        response = requests.get(report_url)

        if response.status_code == 200:
            try:
                report_data = response.json()
            except json.JSONDecodeError:
                return {'error': 'Invalid JSON response from VirusTotal'}

            # Save response to a file
            try:
                with open(f'{file_hash}_virustotal_report.json', 'w') as file:
                    json.dump(report_data, file, indent=4)
            except IOError as e:
                return {'error': f'Error writing file: {e}'}

            return report_data

        elif response.status_code == 403:
            return {'error': 'Access denied, check your API key'}
        elif response.status_code == 404:
            return {'error': 'No report found for the provided hash'}
        else:
            return {'error': f'Request failed with status code {response.status_code}'}

    except requests.RequestException as request_error:
        return {'error': f'HTTP request error: {request_error}'}
    
def get_virustotal_hash_values(hash):
    """
    Retrieve hash values from VirusTotal API.
    """
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
