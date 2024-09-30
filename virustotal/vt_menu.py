# vt_menu.py

import os
from . import vt_display, vt_androguard, vt_analysis, vt_requests, vt_utils
from utils import user_prompts, app_display

def virustotal_menu():
    while True:
        menu_title = "VirusTotal Analysis Menu"
        menu_options = {
            1: "Submit a sample",
            2: "Read hash file data",
            3: "Test connection to Virustotal.com",
            4: "Ping 8.8.8.8"
        }
        app_display.display_menu(menu_title, menu_options)
        user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(5)])

        # exit
        if user_choice == '0':
            break
        
        # submit to virustotal.com
        elif user_choice == '1':
            menu_title = "VirusTotal Submission:"
            menu_options = {1: "APK", 2: "Hash"}
            app_display.display_menu(menu_title, menu_options)
            choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2'])

            # Return to menu
            if choice == '0':
                return
            
            # Submit APK
            elif choice == '1':
                response = submit_apk()
                if response:
                    handle_response_data(response, "APK")
            
            # Submit Hash
            elif choice == '2':
                response = submit_hash()
                if response:
                    handle_response_data(response, "Hash")

        # analysis hash data input
        elif user_choice == '2':
            vt_analysis.analyze_hash_data()
        
        # check connection to virustotal.com
        elif user_choice == '3':
            vt_utils.check_virustotal_access()
        
        # check 8.8.8.8
        elif user_choice == '4':
            vt_utils.check_ping()
        
        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

        user_prompts.pause_until_keypress()

def handle_response_data(response, sample_type):
    report_data = vt_analysis.process_vt_response(response, sample_type)

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
        
        elif choice == "1": # display report
            # vt_analysis.display_report(report_data)
            print("TODO: display virustotal report [!!]")
        
        elif choice == "2": # save report
            # vt_analysis.write_report_to_file(report_data) # 
            print("TODO: save virustotal report [!!]")
        
        elif choice == "3":
            display_androguard_data(response)
        
        elif choice == "4":
            vt_display.display_summary_statistics(report_data)
        
        elif choice == "5":
            vt_display.display_detection_breakdown(report_data)
        
        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

def display_androguard_data(response):
    androguard = vt_androguard.handle_androguard_response(response)
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
                vt_display.display_main_activity(androguard)
            
            elif choice == "2":
                vt_display.display_manifest_components(androguard)
            
            elif choice == "3":
                vt_display.display_certificate_details(androguard)
            
            elif choice == "4":
                vt_display.display_permissions(androguard)
            
            elif choice == "5":
                vt_display.display_intent_filters(androguard)
            
            else:
                print("Invalid choice.")

def submit_apk():
    apk_file_path = user_prompts.user_enter_apk_path()
    if os.path.isfile(apk_file_path):
        try:
            return vt_requests.query_apk(apk_file_path, 'hash')
        except Exception as e:
            print(f"Error submitting the APK: {e}")
    else:
        print("Invalid APK file path.")

def submit_hash():
    hash_value = user_prompts.user_enter_hash_ioc()
    try:
        return vt_requests.query_virustotal(hash_value, 'hash')
    
    except Exception as e:
        print(f"Error submitting the hash: {e}")
