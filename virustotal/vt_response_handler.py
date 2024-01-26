import matplotlib.pyplot as plt
import json
import os
from tabulate import tabulate

from . import vt_androguard

def save_json_response(response, filename, overwrite=False):
    try:
        if os.path.exists(filename) and not overwrite:
            print(f"File '{filename}' already exists. Use 'overwrite=True' to overwrite.")
        else:
            with open(filename, 'w') as file:
                json.dump(response, file, indent=4)
            print(f"Response saved to '{filename}'")
    except Exception as e:
        print(f"Error saving response to file: {e}")

def detailed_detection_breakdown(attributes):
    if 'last_analysis_results' in attributes:
        print("\nDetailed Detection Breakdown:")
        headers = ["Engine", "Detected", "Result", "Engine Update"]
        data = []

        # Sort the results by engine
        sorted_results = sorted(attributes['last_analysis_results'].items(), key=lambda x: x[0])

        for engine, result in sorted_results:
            detected = result.get('category', 'N/A')
            
            detection_result = result.get('result', 'N/A')
            if not detection_result:
                continue

            # Ensure all fields are not None
            if None not in [detected, detection_result]:
                data.append([engine, detected, detection_result])
            else:
                data.append([engine, "Incomplete Data", "", ""])

        if data:
            print(tabulate(data, headers=headers, tablefmt="fancy_grid"))
        else:
            print("No data available for detailed detection breakdown.")

def summary_statistics(attributes):
    if 'last_analysis_stats' in attributes:
        stats = attributes['last_analysis_stats']
        print("\nSummary Statistics:")
        print(f"  Total Detections: {stats['malicious']}")
        print(f"  Total Harmless: {stats['harmless']}")
        print(f"  Total Undetected: {stats['undetected']}")
        print(f"  Total Suspicious: {stats['suspicious']}")

def display_hash_values(attributes):
    print("\nHash Values:")
    md5_hash = attributes.get('md5', 'N/A')
    sha1_hash = attributes.get('sha1', 'N/A')
    sha256_hash = attributes.get('sha256', 'N/A')

    if md5_hash != 'N/A':
        print(f"MD5:    {md5_hash}")
    if sha1_hash != 'N/A':
        print(f"SHA1:   {sha1_hash}")
    if sha256_hash != 'N/A':
        print(f"SHA256: {sha256_hash}")

def visualize_detection_stats(attributes, save_filename=None):

    if 'last_analysis_stats' in attributes:
        stats = attributes['last_analysis_stats']
        categories = list(stats.keys())
        values = list(stats.values())

        # Create a bar chart with custom colors
        colors = ['#ff9999', '#66b3ff', '#99ff99', '#c2c2f0']

        plt.figure(figsize=(10, 6))
        plt.bar(categories, values, color=colors)

        # Adding labels to the bars
        for i, v in enumerate(values):
            plt.text(i, v + 1, str(v), ha='center', va='bottom')

        # Add a title and labels
        plt.title("Detection Statistics")
        plt.xlabel("Categories")
        plt.ylabel("Counts")

        # Adding a legend
        plt.legend(['Counts'], loc='upper right')

        # Save the image if a filename is provided
        if save_filename:
            plt.savefig(save_filename)
            print(f"Detection statistics image saved to {save_filename}")
        else:
            plt.show()

def historical_analysis(attributes):
    if 'first_seen' in attributes and 'last_seen' in attributes and 'detection_history' in attributes:
        print("\nHistorical Analysis:")
        print(f"  First Seen: {attributes['first_seen']}")
        print(f"  Last Seen: {attributes['last_seen']}")

        print("\nDetection History:")
        for detection in attributes['detection_history']:
            print(f"  Date: {detection['date']}")
            print(f"  Detected: {detection['detected']}")
            print(f"  Detection Count: {detection['detection_count']}")

def behavior_analysis(attributes):
    if 'behaviours' in attributes:
        behaviors = attributes['behaviours']
        print("\nBehavior Analysis:")
        for behavior in behaviors:
            print(f"  Behavior Name: {behavior['name']}")
            print(f"  Description: {behavior['description']}")
            print(f"  Severity: {behavior['severity']}")
            print(f"  Confidence: {behavior['confidence']}")

def network_traffic_analysis(attributes):
    if 'network_traffic' in attributes:
        network_traffic = attributes['network_traffic']
        print("\nNetwork Traffic Analysis:")
        for entry in network_traffic:
            print(f"  Timestamp: {entry['timestamp']}")
            print(f"  Protocol: {entry['protocol']}")
            print(f"  Source IP: {entry['src_ip']}")
            print(f"  Destination IP: {entry['dst_ip']}")
            print(f"  Destination Port: {entry['dst_port']}")

def parse_response(response):
    if response and 'data' in response:
        data = response['data']
        print(f"\nID: {data['id']}")
        print(f"VirusTotal Link: {data['links']['self']}")
        
        if 'attributes' in data:
            attributes = data['attributes']
            
            #display_hash_values(attributes)
            #summary_statistics(attributes)

            #vt_androguard.display_data(attributes)
            vt_androguard.display_androguard_data(attributes)
            
            #save_filename = "detection_stats.png"
            #visualize_detection_stats(attributes, save_filename)
            
            # Historical Analysis
            #historical_analysis(attributes)

            # Behavior Analysis
            #behavior_analysis(attributes)

            # Network Traffic Analysis
            #network_traffic_analysis(attributes)

            #detailed_detection_breakdown(attributes)

    else:
        print("No data found for the given input.")

    #input("\nPress Enter to continue.")