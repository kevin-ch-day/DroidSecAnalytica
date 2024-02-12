# vt_menu.py

from . import vt_utils, vt_androguard, vt_analysis
from utils import user_prompts, app_display

def virustotal_menu():
    while True:
        menu_title = "VirusTotal Analysis Menu"
        menu_options = {
            1: "Submit a sample",
            2: "Run Database Analysis",
            3: "Check Virustotal API Key",
            4: "Check Virustotal.com Connection",
            5: "Check Internet Connection"
        }
        app_display.display_menu(menu_title, menu_options)
        user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(6)])

        if user_choice == '0':
            break
        elif user_choice == '1':
            handle_sample_submission()
        elif user_choice == '2':
            vt_analysis.run_analysis()
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
    menu_title = "VirusTotal.com Sample Submission:"
    menu_options = {
        1: "APK",
        2: "Hash"
    }
    app_display.display_menu(menu_title, menu_options)
    choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2'])

    if choice == '0':
        return
    
    elif choice == '1':
        response = vt_utils.submit_apk()
        vt_analysis.user_vt_data_processing(response)
        
    elif choice == '2':
        response = vt_utils.submit_hash()
        vt_analysis.user_vt_data_processing(response)

    if response:
        handle_response_data(response)

def handle_response_data(response):
    report_data = vt_analysis.parse_virustotal_response(response)

    while True:
        menu_title = "Data Results"
        menu_options = {
            1: "Display results",
            2: "Save results to file",
            3: "Display Androguard data",
            4: "View summary statistics",
            5: "View detection breakdown"
        }
        app_display.display_menu(menu_title, menu_options)

        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2', '3', '4', '5'])

        if choice == "0":
            return
        elif choice == "1":
            vt_analysis.display_report(report_data)
        elif choice == "2":
            vt_analysis.write_report_to_file(report_data)
            print("Report saved to file.")
        elif choice == "3":
            display_androguard_data(response)
        elif choice == "4":
            vt_utils.view_summary_statistics(report_data)
        elif choice == "5":
            vt_utils.view_detection_breakdown(report_data)
        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

def display_androguard_data(response):
    androguard = vt_androguard.androguard_data(response)
    if androguard:
        while True:
            menu_title = "Androguard Data"
            menu_options = {
                1: "Main Activity and Package Info",
                2: "Manifest Components",
                3: "Certificate Details",
                4: "Permissions",
                5: "Intent Filters"
            }
            
            app_display.display_menu(menu_title, menu_options)
            choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2', '3', '4', '5'])

            if choice == "0":
                break
            elif choice == "1":
                vt_utils.display_main_activity(androguard)
            elif choice == "2":
                vt_utils.display_manifest_components(androguard)
            elif choice == "3":
                vt_utils.display_certificate_details(androguard)
            elif choice == "4":
                vt_utils.display_permissions(androguard)
            elif choice == "5":
                vt_utils.display_intent_filters(androguard)
            else:
                print("Invalid choice.")
