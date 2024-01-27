import os
from . import vt_requests, vt_response, vt_utils, vt_database_hash_analysis
from utils import user_prompts, app_display

# Existing display_menu() function is retained as is
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
            vt_database_hash_analysis.run_analysis()
        elif user_choice == '3':
            check_virustotal_api_key()
        elif user_choice == '4':
            vt_utils.check_virustotal_access()
        elif user_choice == '5':
            vt_utils.check_ping()
        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

        user_prompts.pause_until_keypress()

def handle_sample_submission():
    print("Submit a sample to virustotal")
    print("1. APK File")
    print("2. Hash IOC")
    print("0. Exit")
    sample_choice = user_prompts.user_menu_choice("Enter your choice: ", ['0', '1', '2'])
    if sample_choice == '0':
        return
    elif sample_choice == '1':
        submit_apk()
    elif sample_choice == '2':
        submit_hash()

def submit_apk():
    apk_file_path = user_prompts.user_enter_apk_path()
    if os.path.isfile(apk_file_path):
        try:
            return vt_requests.query_apk(apk_file_path)                
        except Exception as e:
            print(f"Error submitting the apk: {e}")
    else:
        print("Invalid APK file path.")

def submit_hash():
    hash_value = user_prompts.user_enter_hash_ioc()
    try:
        return vt_requests.query_hash(hash_value)
    except Exception as e:
        print(f"Error submitting the hash: {e}")

def check_virustotal_api_key():
    print("Check Virustotal API Key")
    # Logic to check Virustotal API Key
