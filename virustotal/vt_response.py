from utils import logging_utils

def analyze_response(response):
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

        return analysis_result

    except Exception as e:
        logging_utils.log_error(f"Error in analyze_virus_total_response: {e}")
        return None

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