import os
import requests
import socket
import subprocess
import platform

from . import vt_requests
from . import vt_response_handler
from utils import user_prompts, logging_utils, app_display

def is_file_path(input_str):
    return os.path.isfile(input_str)

def apk_analysis():
    apk_file_path = user_prompts.user_enter_apk_path()
    if is_file_path(apk_file_path):
        try:
            result = vt_requests.query_apk(apk_file_path)
            if result:
                vt_response_handler.save_json_response(result, "apk_analysis.json")
                vt_response_handler.parse_response(result)
            else:
                print("Error in processing the APK file request.")
        except Exception as e:
            print(f"An error occurred during APK analysis: {e}")
    else:
        print("Invalid APK file path.")

def hash_analysis():
    hash_value = user_prompts.user_enter_hash_ioc()
    try:
        result = vt_requests.query_hash(hash_value)
        if result:
            vt_response_handler.save_json_response(result, "hash_analysis.json")
            vt_response_handler.parse_response(result)
        else:
            print("Error in processing the hash.")
    except Exception as e:
        print(f"An error occurred during hash analysis: {e}")

def check_api_key():
    # Placeholder for API key check functionality
    print("API key check functionality is not implemented yet.")

def check_virustotal_access():
    url = 'https://www.virustotal.com'
    try:
        host = socket.gethostbyname('www.virustotal.com')
        print("DNS resolution successful.")
    except socket.gaierror:
        print("Failed to resolve VirusTotal's domain. Check your DNS settings.")
        return False

    try:
        socket.create_connection((host, 80), 2)
        print("Network connection to VirusTotal established.")
    except OSError:
        print("Network connection to VirusTotal failed. Check your network.")
        return False

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print("Successfully connected to VirusTotal.")
            return True
        else:
            print(f"Connected to VirusTotal, but received a non-success status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"HTTP request to VirusTotal failed: {e}")
        return False

def check_ping():
    ip = "8.8.8.8"
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ["ping", param, "1", ip]

    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if response.returncode == 0:
            print(f"Successfully pinged {ip}.")
            return True
        else:
            print(f"Failed to ping {ip}. Response: {response.stderr}")
            return False
    except Exception as e:
        print(f"An error occurred while trying to ping: {e}")
        return False

def display_menu():
    print(app_display.format_menu_title("VirusTotal Analysis Menu"))
    print(app_display.format_menu_option(1, "APK Analysis"))
    print(app_display.format_menu_option(2, "Hash Analysis"))
    print(app_display.format_menu_option(3, "Check Virustotal API Key"))
    print(app_display.format_menu_option(4, "Check Virustotal.coms"))
    print(app_display.format_menu_option(5, "Check Internet Connection"))
    print(app_display.format_menu_option(0, "Return"))

def virustotal_menu():
    while True:
        display_menu()
        user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(6)])  # range updated to 6

        # Return to static analysis menu
        if user_choice == '0':
            break

        # Virustotal APK Analysis
        elif user_choice == '1':
            apk_analysis()

        # Virustotal Hash Analysis
        elif user_choice == '2':
            hash_analysis()

        # Check Virustotal API Key
        elif user_choice == '3':
            handle_api_integration()

        # Check connection to virustotal.com
        elif user_choice == '4':
            print("Checking connection to Virustotal.com...")
            check_virustotal_access()

        # Check Internet connection
        elif user_choice == '5':
            print("Checking Internet connection...")
            check_ping()

        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

        user_prompts.pause_until_keypress()

def handle_api_integration():
    try:
        #virustotal_checker = VirustotalChecker()
        virustotal_checker = None
        api_key_valid = virustotal_checker.check_api_key()

        if api_key_valid:
            logging_utils.log_info("Virustotal API Key is valid.")
            print("Virustotal API Key is valid.")
        else:
            logging_utils.log_error("Virustotal API Key is invalid or exceeded the rate limit.")
            print("Virustotal API Key is invalid or exceeded the rate limit.")
    
    except Exception as e:
        logging_utils.log_error(f"An error occurred during Virustotal API Key check: {e}", exc_info=True)
        print("An error occurred during Virustotal API Key check. Please check the logs for more details.")
