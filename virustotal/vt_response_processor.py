
def print_date_info(attributes):
    print(f"  First Seen: {attributes.get('first_seen', 'N/A')}")
    print(f"  Last Seen: {attributes.get('last_seen', 'N/A')}")

def print_detection_history(attributes):
    for detection in attributes.get('detection_history', []):
        print(f"  Date: {detection.get('date', 'N/A')}")
        print(f"  Detected: {detection.get('detected', 'N/A')}")
        print(f"  Detection Count: {detection.get('detection_count', 'N/A')}")

def historical_analysis(attributes):
    if 'first_seen' in attributes or 'last_seen' in attributes or 'detection_history' in attributes:
        print("\nHistorical Analysis:")
        print_date_info(attributes)
        print("\nDetection History:")
        print_detection_history(attributes)

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