from tabulate import tabulate
from utils import logging_utils

from . import AndroguardADT
from . import vt_androguard
from . import display_androguard_data

def parse_response(response):
    if 'data' not in response:
        print("No 'data' key in response.")
        return

    data = response.get('data', {})
    attributes = data.get('attributes', {})
    if not attributes or not isinstance(attributes, dict):
        print("No valid attributes found in the data.")
        return
    
    try:
        if 'last_analysis_stats' in attributes:
            stats = attributes['last_analysis_stats']
            print("\nSummary Statistics:")
            for key, value in stats.items():
                print(f"  Total {key.capitalize()}: {value}")

        if androguard_data := parse_androguard_data(attributes):
            display_androguard_data.display_main_activity(androguard_data)
            display_androguard_data.display_manifest_components(androguard_data)
            display_androguard_data.display_certificate_details(androguard_data)
            display_androguard_data.display_permissions(androguard_data.get_permissions())
            display_androguard_data.display_intent_filters(androguard_data)
        historical_analysis(attributes)
        behavior_analysis(attributes)
        network_traffic_analysis(attributes)
        detailed_detection_breakdown(attributes)
        
    except Exception as e:
        logging_utils.log_error(f"Error processing response attributes: {e}")

def parse_androguard_data(attributes):
    try:
        data = attributes.get('androguard', None)
        if not data:
            return None

        androguard_data = AndroguardADT.AndroguardADT()
        vt_androguard.parse_basic_data(androguard_data, data)
        vt_androguard.parse_permissions(androguard_data, data)
        vt_androguard.parse_certificate_data(androguard_data, data)
        vt_androguard.parse_intent_filters(androguard_data, data)
        return androguard_data

    except Exception as e:
        logging_utils.log_error(f"Error parsing Androguard data: {str(e)}")
        return None

def historical_analysis(attributes):
    if 'first_seen' in attributes or 'last_seen' in attributes or 'detection_history' in attributes:
        print("\nHistorical Analysis:")
        print(f"  First Seen: {attributes.get('first_seen', 'N/A')}")
        print(f"  Last Seen: {attributes.get('last_seen', 'N/A')}")
        
        print("\nDetection History:")
        for detection in attributes.get('detection_history', []):
            print(f"  Date: {detection.get('date', 'N/A')}")
            print(f"  Detected: {detection.get('detected', 'N/A')}")
            print(f"  Detection Count: {detection.get('detection_count', 'N/A')}")

def behavior_analysis(attributes):
    behaviors = attributes.get('behaviours', [])
    if behaviors:
        print("\nBehavior Analysis:")
        for behavior in behaviors:
            print(f"  Behavior Name: {behavior.get('name', 'N/A')}")
            print(f"  Description: {behavior.get('description', 'N/A')}")
            print(f"  Severity: {behavior.get('severity', 'N/A')}")
            print(f"  Confidence: {behavior.get('confidence', 'N/A')}")

def network_traffic_analysis(attributes):
    network_traffic = attributes.get('network_traffic', [])
    if network_traffic:
        print("\nNetwork Traffic Analysis:")
        for entry in network_traffic:
            print(f"  Timestamp: {entry.get('timestamp', 'N/A')}")
            print(f"  Protocol: {entry.get('protocol', 'N/A')}")
            print(f"  Source IP: {entry.get('src_ip', 'N/A')}")
            print(f"  Destination IP: {entry.get('dst_ip', 'N/A')}")
            print(f"  Destination Port: {entry.get('dst_port', 'N/A')}")

def detailed_detection_breakdown(scan_results, table_format="fancy_grid"):
    if 'last_analysis_results' in scan_results:
        print("\nDetailed Detection Breakdown:")
        headers = ["Engine", "Detected", "Result", "Engine Update"]
        detection_data = []

        sorted_results = sorted(scan_results['last_analysis_results'].items(), key=lambda engine_data: engine_data[0])
        for engine, label in sorted_results:
            result = label.get('result', 'N/A')
            if result:
                detection_data.append([engine, result])

        if detection_data:
            print(tabulate(detection_data, headers=headers, tablefmt=table_format))
        else:
            print("No data available for detailed detection breakdown.")

