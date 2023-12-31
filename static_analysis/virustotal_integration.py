import os
import logging
import requests

LOG_FILE = 'logs/static_analysis.log'

def virustotal_scan(api_key, file_paths):
    try:
        print(f"Performing VirusTotal.com web scan...")
        scan_results = web_scan(api_key, file_paths[0])
        if not scan_results:
            print("No results generated from irusTotal.com web scan.")
        else:
            print("Saving scan results.")
            save_scan_results(scan_results)

    except Exception as e:
        logging.error(f"Error during VirusTotal scan: {e}")

def web_scan(api_key, file_path):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': api_key}
        files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}

        response = requests.post(url, files=files, params=params)
        response_json = response.json()

        if 'resource' in response_json:
            resource_url = response_json['resource']
            print(f"File submitted for scanning with resource URL: {resource_url}")
            return check_scan_status(api_key, resource_url)
        else:
            logging.error(f"VirusTotal scan failed: {response_json}")
            return None

    except Exception as e:
        logging.error(f"Error scanning file with VirusTotal: {e}")
        return None

def check_scan_status(api_key, resource_url):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': resource_url, 'allinfo': 1}
        response = requests.get(url, params=params)
        response_json = response.json()

        if 'scans' in response_json:
            print("Scan completed. Retrieving scan results...")
            return response_json

        logging.error(f"Error checking scan status with VirusTotal: {response_json}")
        return None

    except Exception as e:
        logging.error(f"Error checking scan status with VirusTotal: {e}")
        return None

def save_scan_results(scan_results):
    with open('output/virustotal_results.txt', 'w') as result_file:
        for file_path, scan_result in scan_results.items():
            print(f"Saving scan results for {os.path.basename(file_path)}...")
            result_file.write(f"Results for file: {os.path.basename(file_path)}\n")
            
            print("\nwrite_virustotal_results()")
            write_virustotal_results(result_file, scan_result)

            print("\nwrite_security_vendors_analysis()")
            write_security_vendors_analysis(result_file, scan_result)
            result_file.write("=" * 60 + "\n\n")
            print(f"Scan results saved for {os.path.basename(file_path)}.")

def write_virustotal_results(result_file, scan_result):
    scan_id = scan_result.get('scan_id', '')
    md5_hash = scan_result.get('md5', '')
    sha1_hash = scan_result.get('sha1', '')
    sha256_hash = scan_result.get('sha256', '')
    scan_date = scan_result.get('scan_date', '')
    positives = scan_result.get('positives', 0)
    total = scan_result.get('total', 0)
    scan_report_url = scan_result.get('permalink', '')

    result_file.write("VirusTotal Scan Result:\n")
    result_file.write(f"Scan ID: {scan_id}\n")
    result_file.write(f"MD5 Hash: {md5_hash}\n")
    result_file.write(f"SHA1 Hash: {sha1_hash}\n")
    result_file.write(f"SHA256 Hash: {sha256_hash}\n")
    result_file.write(f"Scan Date: {scan_date}\n")
    result_file.write(f"Positives/Total: {positives}/{total}\n")
    result_file.write(f"Scan Report URL: {scan_report_url}\n")

    if positives > 0:
        result_file.write("WARNING: This file has been detected as malicious by one or more antivirus engines.\n")
        print("WARNING: This file has been detected as malicious by one or more antivirus engines.")

def write_security_vendors_analysis(result_file, scan_result):
    security_vendors = scan_result.get('scans', {})
    
    if security_vendors:
        result_file.write("Security Vendors' Analysis:\n")
        for vendor, analysis in security_vendors.items():
            vendor_name = vendor.replace("_", " ").title()
            detected = analysis.get('detected', False)
            result = analysis.get('result', '')
            if detected:
                result_file.write(f"{vendor_name}: {result}\n")
                print(f"{vendor_name}: {result}")
