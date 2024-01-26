import os

from . import vt_requests, vt_response_handler, vt_utils
from utils import user_prompts, app_display

def display_menu():
    print(app_display.format_menu_title("VirusTotal Analysis Menu"))
    print(app_display.format_menu_option(1, "APK Analysis"))
    print(app_display.format_menu_option(2, "Hash Analysis"))
    print(app_display.format_menu_option(3, "Check Virustotal API Key"))
    print(app_display.format_menu_option(4, "Check Virustotal.com"))
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
            check_api_key()

        # Check connection to virustotal.com
        elif user_choice == '4':
            print("Checking connection to Virustotal.com...")
            vt_utils.check_virustotal_access()

        # Check Internet connection
        elif user_choice == '5':
            print("Checking Internet connection...")
            vt_utils.check_ping()

        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

        user_prompts.pause_until_keypress()

def is_file_path(input_str):
    return os.path.isfile(input_str)

def apk_analysis():
    apk_file_path = user_prompts.user_enter_apk_path()
    if is_file_path(apk_file_path):
        try:
            result = vt_requests.query_apk(apk_file_path)
            if result:
                vt_response_handler.save_json_response(result, "output/apk_analysis.json")
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
            vt_response_handler.save_json_response(result, "output/hash_analysis.json")
            vt_response_handler.parse_response(result)
        else:
            print("Error in processing the hash.")
    except Exception as e:
        print(f"An error occurred during hash analysis: {e}")

def check_api_key():
    vt_utils.handle_api_integration()
