from utils import logging_utils
from datetime import datetime

def generate_report(response):
    try:
        data = response.get('data', {})
        if not data:
            raise ValueError("No 'data' key in response.")

        attributes = data.get('attributes', {})
        if not attributes:
            raise ValueError("No valid attributes found in the data.")

        analysis_result = {}

        # Extracting summary statistics
        summary_statistics = attributes.get('last_analysis_stats', {})
        if summary_statistics:
            analysis_result['summary_statistics'] = {
                key.capitalize(): value
                for key, value in summary_statistics.items()
            }

        # Adding additional analysis
        analysis_result['historical_analysis'] = parse_historical_analysis(attributes)
        analysis_result['behavior_analysis'] = parse_behavior_analysis(attributes)
        analysis_result['network_traffic_analysis'] = parse_network_traffic(attributes)
        analysis_result['detection_breakdown'] = parse_engine_detection(attributes)

        # Prepare data for report
        report = {
            "Report URL": data['links']['self'],
            "VirusTotal Threat Label": attributes['popular_threat_classification']['suggested_threat_label'],
            "File Size": format_file_size(attributes['size']),
            "MD5": attributes['md5'],
            "SHA1": attributes['sha1'],
            "SHA256": attributes['sha256'],
            "Last Submission Date": format_timestamp(attributes['last_submission_date']),
            "First Seen": format_timestamp(attributes['first_seen_itw_date']),
            "Last Analysis Date": format_timestamp(attributes['last_analysis_date']),
            "Other Names": sorted(attributes['names']),
        }
        report["Analysis Result"] = analysis_result

        return report

    except Exception as e:
        logging_utils.log_error(f"Error in analyze_and_generate_report: {e}")
        return None

def format_timestamp(timestamp):
    try:
        # Check if the timestamp is in milliseconds and convert to seconds if necessary
        if isinstance(timestamp, (int, float)) and timestamp > 1e10:  # milliseconds
            timestamp /= 1000

        # Format timestamp to include AM or PM
        return datetime.fromtimestamp(timestamp).strftime('%I:%M:%S %p %m-%d-%Y') if timestamp else 'N/A'
    except (TypeError, ValueError, OverflowError):
        return 'Invalid Timestamp'

def format_file_size(size):
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def print_report(report):
    print("\nVirusTotal Report:")

    # General Information Section
    print("\nGeneral Information:")
    print(f"Report URL:".ljust(25), report["Report URL"])
    print(f"VirusTotal Threat Label:".ljust(25), report["VirusTotal Threat Label"])
    print(f"File Size:".ljust(25), report["File Size"])
    print(f"MD5:".ljust(25), report["MD5"])
    print(f"SHA1:".ljust(25), report["SHA1"])
    print(f"SHA256:".ljust(25), report["SHA256"])
    print(f"Last Submission Date:".ljust(25), report["Last Submission Date"])
    print(f"First Seen:".ljust(25), report["First Seen"])
    print(f"Last Analysis Date:".ljust(25), report["Last Analysis Date"])

    # Other Names Section
    print("\nOther Names:")
    for item in report["Other Names"]:
        print(f"  - {item}")

    # Analysis Summary
    print("\nAnalysis Summary:")
    print("File is classified as:", report["VirusTotal Threat Label"])
    print("Overall Status: (not implemented)")  # Add your analysis here
    print("Additional Details: (not implemented)")  # Add more analysis details here

    print()

def parse_historical_analysis(attributes):
    historical_analysis = {}
    if 'first_seen' in attributes or 'last_seen' in attributes or 'detection_history' in attributes:
        historical_analysis['first_seen'] = attributes.get('first_seen', 'N/A')
        historical_analysis['last_seen'] = attributes.get('last_seen', 'N/A')
        historical_analysis['detection_history'] = attributes.get('detection_history', [])
    return historical_analysis

def parse_behavior_analysis(attributes):
    behaviors = attributes.get('behaviours', [])
    behavior_analysis = []
    for behavior in behaviors:
        behavior_analysis.append({
            'name': behavior.get('name', 'N/A'),
            'description': behavior.get('description', 'N/A'),
            'severity': behavior.get('severity', 'N/A'),
            'confidence': behavior.get('confidence', 'N/A')
        })
    return behavior_analysis

def parse_network_traffic(attributes):
    network_traffic = attributes.get('network_traffic', [])
    network_analysis = []
    for entry in network_traffic:
        network_analysis.append({
            'timestamp': entry.get('timestamp', 'N/A'),
            'protocol': entry.get('protocol', 'N/A'),
            'src_ip': entry.get('src_ip', 'N/A'),
            'dst_ip': entry.get('dst_ip', 'N/A'),
            'dst_port': entry.get('dst_port', 'N/A')
        })
    return network_analysis

def parse_engine_detection(attributes, table_format="fancy_grid"):
    detailed_breakdown = []
    if 'last_analysis_results' in attributes:
        sorted_results = sorted(attributes['last_analysis_results'].items(), key=lambda engine_data: engine_data[0])
        for engine, label in sorted_results:
            result = label.get('result', 'N/A')
            if result:
                detailed_breakdown.append([engine, result])
    return detailed_breakdown