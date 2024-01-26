import json
import os
from tabulate import tabulate
from . import vt_androguard, vt_response_processor
from utils import logging_utils

def parse_response(response, debug=False):
    if not response:
        logging_utils.log_error("Received an empty response.")
        return

    if 'data' not in response:
        logging_utils.log_error("No 'data' key in response.")
        return

    data = response.get('data', {})
    response_id = data.get('id', 'N/A')
    virus_total_link = data.get('links', {}).get('self', 'N/A')

    if debug:
        logging_utils.log_debug(f"Response ID: {response_id}")
        logging_utils.log_debug(f"VirusTotal Link: {virus_total_link}")

    attributes = data.get('attributes', {})
    if not attributes:
        logging_utils.log_warning("No attributes found in the data.")
        return

    try:
        #summary_statistics(attributes)
        vt_androguard.display_androguard_data(attributes)
        #vt_response_processor.historical_analysis(attributes)
        #vt_response_processor.behavior_analysis(attributes)
        #vt_response_processor.network_traffic_analysis(attributes)
        #detailed_detection_breakdown(attributes)
        
    except Exception as e:
        logging_utils.log_error(f"Error processing response attributes: {e}")


def save_json_response(response, filename, overwrite=True):
    if not isinstance(response, dict):
        print("Error: Response must be a dictionary.")
        return

    try:
        if os.path.exists(filename) and not overwrite:
            print(f"File '{filename}' already exists. Use 'overwrite=True' to overwrite.")
            return

        with open(filename, 'w') as file:
            json.dump(response, file, indent=4)
        print(f"Response saved to '{filename}'")
    except Exception as e:
        print(f"Error saving response to file: {e}")

def detailed_detection_breakdown(attributes, table_format="fancy_grid"):
    if not isinstance(attributes, dict):
        print("Error: Attributes must be a dictionary.")
        return

    if 'last_analysis_results' in attributes:
        print("\nDetailed Detection Breakdown:")
        headers = ["Engine", "Detected", "Result", "Engine Update"]
        data = []

        sorted_results = sorted(attributes['last_analysis_results'].items(), key=lambda x: x[0])

        for engine, result in sorted_results:
            detected = result.get('category', 'N/A')
            detection_result = result.get('result', 'N/A')

            if detection_result:
                data.append([engine, detected, detection_result])

        if data:
            print(tabulate(data, headers=headers, tablefmt=table_format))
        else:
            print("No data available for detailed detection breakdown.")

def summary_statistics(attributes):
    if not isinstance(attributes, dict):
        print("Error: Attributes must be a dictionary.")
        return

    if 'last_analysis_stats' in attributes:
        stats = attributes['last_analysis_stats']
        print("\nSummary Statistics:")
        for key, value in stats.items():
            print(f"  Total {key.capitalize()}: {value}")

def display_hash_values(attributes):
    if not isinstance(attributes, dict):
        print("Error: Attributes must be a dictionary.")
        return

    print("\nHash Values:")
    for hash_type in ['md5', 'sha1', 'sha256']:
        hash_value = attributes.get(hash_type, 'N/A')
        if hash_value != 'N/A':
            print(f"{hash_type.upper()}: {hash_value}")