import os
from . import vt_requests, vt_response, vt_utils
from utils import user_prompts, app_display

def display_menu():
    print(app_display.format_menu_title("VirusTotal Analysis Menu"))
    print(app_display.format_menu_option(1, "Submit a sample"))
    print(app_display.format_menu_option(2, "Run VirusTotal Database Analysis"))
    print(app_display.format_menu_option(3, "Check Virustotal API Key"))
    print(app_display.format_menu_option(4, "Check Virustotal.com"))
    print(app_display.format_menu_option(5, "Check Internet Connection"))
    print(app_display.format_menu_option(0, "Return"))

def virustotal_menu():
    while True:
        display_menu()
        user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(6)])

        if user_choice == '0':
            break
        elif user_choice == '1':
            handle_sample_submission()
        elif user_choice == '2':
            vt_response.run_analysis()
        elif user_choice == '3':
            print("Check Virustotal API Key")
        elif user_choice == '4':
            vt_utils.check_virustotal_access()
        elif user_choice == '5':
            vt_utils.check_ping()
        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

        user_prompts.pause_until_keypress()

def handle_sample_submission():
    print("\nSubmit a sample to VirusTotal")
    print("1. APK File")
    print("2. Hash IOC")
    print("0. Exit")

    sample_choice = user_prompts.user_menu_choice("Enter your choice: ", ['0', '1', '2'])
    
    if sample_choice == '0':
        return
    elif sample_choice == '1':
        submit_and_display_results(submit_apk)
    elif sample_choice == '2':
        submit_and_display_results(submit_hash)
    else:
        print("Invalid choice. Please try again.")

def submit_apk():
    apk_file_path = user_prompts.user_enter_apk_path()
    if os.path.isfile(apk_file_path):
        try:
            return vt_requests.query_apk(apk_file_path)                
        except Exception as e:
            print(f"Error submitting the APK: {e}")
    else:
        print("Invalid APK file path.")

def submit_hash():
    hash_value = user_prompts.user_enter_hash_ioc()
    try:
        return vt_requests.query_hash(hash_value)
    except Exception as e:
        print(f"Error submitting the hash: {e}")

def submit_and_display_results(submit_function):
    result = submit_function()
    if result:
        data = vt_response.analyze_response(result)
        print("\nAnalysis Results:")

        # Displaying Summary Statistics
        print_summary_statistics(data.get('summary_statistics', {}))

        # Displaying Historical Analysis
        print_historical_analysis(data.get('historical_analysis', {}))

        # Displaying Behavior Analysis
        print_behavior_analysis(data.get('behavior_analysis', []))

        # Displaying Network Traffic Analysis
        print_network_traffic_analysis(data.get('network_traffic_analysis', []))

        # Displaying Detection Breakdown
        print_detection_breakdown(data.get('detection_breakdown', []))

    else:
        print("No data to analyze.")

def print_summary_statistics(summary_statistics):
    if summary_statistics:
        print("\nSummary Statistics:")
        for key, value in summary_statistics.items():
            print(f"  {key}: {value}")

def print_network_traffic_analysis(network_traffic_analysis):
    if network_traffic_analysis:
        print("\nNetwork Traffic Analysis:")
        for record in network_traffic_analysis:
            print(f"  Timestamp: {record.get('timestamp', 'N/A')}")
            print(f"  Protocol: {record.get('protocol', 'N/A')}")
            print(f"  Source IP: {record.get('src_ip', 'N/A')}")
            print(f"  Destination IP: {record.get('dst_ip', 'N/A')}")
            print(f"  Destination Port: {record.get('dst_port', 'N/A')}")
    else:
        print("No network traffic analysis data.")

def print_behavior_analysis(behavior_analysis):
    if behavior_analysis:
        print("\nBehavior Analysis:")
        for behavior in behavior_analysis:
            print(f"  Behavior Name: {behavior.get('name', 'N/A')}")
            print(f"  Description: {behavior.get('description', 'N/A')}")
            print(f"  Severity: {behavior.get('severity', 'N/A')}")
    else:
        print("No behavior analysis data.")


def print_historical_analysis(historical_analysis):
    if historical_analysis:
        print("\nHistorical Analysis:")
        # Assuming historical_analysis is a dictionary with relevant keys
        for key, value in historical_analysis.items():
            print(f"  {key}: {value}")
    else:
        print("No historical analysis data.")


def print_detection_breakdown(detection_breakdown):
    if detection_breakdown:
        print("\nDetection Breakdown:")
        for detection in detection_breakdown:
            print(f"  {detection[0]}: {detection[1]}")
