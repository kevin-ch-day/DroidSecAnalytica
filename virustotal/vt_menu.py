# vt_menu.py

import os
from . import vt_display, vt_androguard, vt_malware_classification, vt_requests, vt_utils, hash_xlsx_data_loader, vt_hash_processing
from utils import user_prompts, app_display, hash_preload

def virustotal_menu():
    while True:
        menu_title = "VirusTotal Analysis Menu"
        menu_options = {
            1: "Submit an APK file for analysis",
            2: "Submit a hash to VirusTotal",
            3: "Analyze hash data from a text file (.txt)",
            4: "Analyze hash data from an Excel file (.xlsx)",
            5: "Check database for unanalyzed hash data",
            6: "Test connection to VirusTotal",
            7: "Validate VirusTotal API keys",
            0: "Exit menu"
        }

        app_display.display_menu(menu_title, menu_options)
        user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(8)])

        # Exit
        if user_choice == '0':
            print("\nExiting VirusTotal Analysis Menu.")
            break

        # Submit an APK file for analysis
        elif user_choice == '1':
            print("[!!] NOT DONE [!!]")
            print("\nSubmit an APK file to VirusTotal.")
            exit()

            # Placeholder for future APK file submission
            apk_file_path = user_prompts.user_enter_apk_path()

            if os.path.isfile(apk_file_path):
                try:
                    print("TODO: vt_requests.query_apk(apk_file_path, 'hash')")
                    response = None

                    if response:
                        print("APK file successfully submitted for analysis.")
                        handle_response_data(response, "APK")
                    else:
                        print("Submission failed. Please try again.")

                except Exception as e:
                    print(f"Error submitting the APK: {e}")
            else:
                print("Invalid APK file path. Please check the file location and try again.")


        # Submit a hash to VirusTotal
        elif user_choice == '2':
            print("\nSubmitting a hash to VirusTotal...")
            hash_value = user_prompts.user_enter_hash_ioc()

            if hash_value:
                try:
                    response = vt_requests.query_virustotal(hash_value, 'hash')
                    if response:
                        print("Hash successfully submitted for analysis.")
                        handle_response_data(response, "Hash")
                    else:
                        print("Submission failed. Please try again.")
                except Exception as e:
                    print(f"Error submitting the hash: {e}")
            else:
                print("Invalid hash input. Please enter a valid hash.")

        # Analyze hash data from a text file
        elif user_choice == '3':
            print("\nLoading and analyzing hash data from a text file (.txt)...")
            result = hash_preload.load_hashes_from_txt()
            if result:
                print("Hash data from the text file successfully analyzed.")
            else:
                print("No valid hash data found in the text file.")

        # Analyze hash data from an Excel file
        elif user_choice == '4':
            hash_xlsx_data_loader.run_xlxs_data_loader()            

        # Check database for unanalyzed hash data
        elif user_choice == '5':
            vt_hash_processing.check_unanalyzed_hashes()

        # Test connection to VirusTotal
        elif user_choice == '6':
            print("\nTesting connection to VirusTotal.com...")
            if vt_utils.check_virustotal_access():
                print("Successfully connected to VirusTotal.")
            else:
                print("Unable to reach VirusTotal. Check your network connection.")

        # Validate VirusTotal API keys
        elif user_choice == '7':
            print("\nValidating VirusTotal API keys...")
            if vt_utils.check_virustotal_api():
                print("API keys are valid and active.")
            else:
                print("Invalid or expired API keys. Please update your API key.")

        # Pause before looping back
        user_prompts.pause_until_keypress()

def handle_response_data(response, sample_type):
    report_data = vt_malware_classification.run_malware_classification(response, sample_type)

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