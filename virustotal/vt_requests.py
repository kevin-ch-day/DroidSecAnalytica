# vt_requests.py

import requests
from . import vt_utils

API_KEY = '30c267c3babffbd22f7ffe6aa97b15d1f0a4f958c3db83431bc909a104b7f14f'
#API_KEY = '848c2f7d2499138423f7416f61b8a3e42d8dd9a429ca9bc6f4f478c590c8eec7'

def set_headers():
    return {"x-apikey": API_KEY}

def handle_api_error(e):
    print(f"HTTP Error: {e.response.status_code} - {e.response.reason}")
    if e.response.content:
        print("Error details:", e.response.content.decode())

def query_hash(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = set_headers()
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    
    except requests.HTTPError as e:
        handle_api_error(e)
    
    except requests.ConnectionError:
        print("Connection Error. Please check your network connection.")
    
    except requests.Timeout:
        print("Request Timed Out.")
    
    except requests.RequestException as e:
        print(f"Error occurred: {e}")
    
    return None

def query_apk(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = set_headers()
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
            return response.json()
    
    except requests.HTTPError as e:
        handle_api_error(e)
    
    except requests.ConnectionError:
        print("Connection Error. Please check your network connection.")
    
    except requests.Timeout:
        print("Request Timed Out.")
    
    except requests.RequestException as e:
        print(f"Error occurred: {e}")

def parse_virustotal_response(response):
    try:
        data = response.get('data', {})
        if not data:
            raise ValueError("No 'data' key in response.")
        
        attributes = data.get('attributes', {})
        if not attributes:
            raise ValueError("No valid attributes found in the data.")

        analysis_result = {}
        summary_statistics = attributes.get('last_analysis_stats', {})
        if summary_statistics:
            analysis_result['summary_statistics'] = {
                key.capitalize(): value
                for key, value in summary_statistics.items()
            }
        
        analysis_result['engine_detection'] = parse_engine_detection(attributes)

        report = {
            "Report URL": data['links']['self'],
            #"VirusTotal Threat Label": attributes['popular_threat_classification']['suggested_threat_label'],
            "Size": attributes['size'],
            "Formatted Size": vt_utils.format_file_size(attributes['size']),
            "MD5": attributes['md5'],
            "SHA1": attributes['sha1'],
            "SHA256": attributes['sha256'],
            "Last Submission Date": vt_utils.format_timestamp(attributes['last_submission_date']),
            #"First Seen": vt_utils.format_timestamp(attributes['first_seen_itw_date']),
            "Last Analysis Date": vt_utils.format_timestamp(attributes['last_analysis_date']),
            "Other Names": sorted(attributes['names']),
        }
        report["Analysis Result"] = analysis_result

        return report

    except Exception as e:
        print(f"Error in analyze_and_generate_report: {e}")
        return None

def parse_engine_detection(attributes):
    detailed_breakdown = []
    if 'last_analysis_results' in attributes:
        sorted_results = sorted(attributes['last_analysis_results'].items(), key=lambda engine_data: engine_data[0])
        for engine, label in sorted_results:
            result = label.get('result', 'N/A')
            if result:
                detailed_breakdown.append([engine, result])
    return detailed_breakdown