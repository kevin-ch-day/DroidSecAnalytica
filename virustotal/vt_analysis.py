from . import vt_response
from . import vt_utils
from . import vt_database_analysis
from . import vt_androguard
from . import vt_androguard_display
from utils import user_prompts, app_display

def display_menu(menu_title, menu_options):
    print(app_display.format_menu_title(menu_title))
    for key, option in menu_options.items():
        print(app_display.format_menu_option(key, option))
    print(app_display.format_menu_option(0, "Return"))

def virustotal_menu():
    while True:
        menu_title = "VirusTotal Analysis Menu"
        menu_options = {
            1: "Submit a sample",
            2: "Run VirusTotal Database Analysis",
            3: "Check Virustotal API Key",
            4: "Check Virustotal.com",
            5: "Check Internet Connection"
        }
        display_menu(menu_title, menu_options)
        user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(6)])

        if user_choice == '0':
            break
        elif user_choice == '1':
            handle_sample_submission()
        elif user_choice == '2':
            vt_database_analysis.run_analysis()
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
    while True:
        print("\nSubmit a sample to VirusTotal")
        print("1. Submit APK File")
        print("2. Submit Hash IOC")
        print("0. Return")

        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2'])

        if choice == '0':
            return
        
        elif choice == '1':
            response = vt_utils.submit_apk()
            
        elif choice == '2':
            response = vt_utils.submit_hash()
        
        else:
            print("Invalid choice. Please try again.")

        if response:
            handle_response_data(response)

def handle_response_data(response):
    report_data = vt_response.generate_report(response)

    while True:
        print("\nData Results")
        print("1. Display results")
        print("2. Write results to file")
        print("3. Display Androguard data")
        print("4. View summary statistics")
        print("5. View detection breakdown")
        print("0. Return")

        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2', '3', '4', '5'])

        if choice == "0":
            return
        elif choice == "1":
            vt_response.display_report(report_data)
        elif choice == "2":
            vt_response.write_report_to_file(report_data)
            print("Report saved to file.")
        elif choice == "3":
            display_androguard_data(response)
        elif choice == "4":
            view_summary_statistics(report_data)
        elif choice == "5":
            view_detection_breakdown(report_data)
        else:
            print("Invalid choice. Please enter a number between 0 and 5.")

def view_summary_statistics(report_data):
    if "Analysis Result" in report_data:
        summary_statistics = report_data["Analysis Result"].get("summary_statistics", {})
        print("\nSummary Statistics:")
        for key, value in summary_statistics.items():
            print(f"{key}:".ljust(25), value)
    else:
        print("Summary statistics not available.")

def view_detection_breakdown(report_data):
    if "Analysis Result" in report_data:
        detection_breakdown = report_data["Analysis Result"].get("engine_detection", [])
        if detection_breakdown:
            print("\nDetection Breakdown:")
            for item in detection_breakdown:
                engine_name, detection_label = item[0], item[1]
                print(f"{engine_name.ljust(30)}: {detection_label}")
        else:
            print("Detection breakdown not available.")
    else:
        print("Detection breakdown not available.")

def display_androguard_data(response):
    androguard = vt_androguard.androguard_data(response)
    if androguard:
        while True:
            print("\nAndroguard Data")
            print("1. Display Main Activity and Package Info")
            print("2. Display Manifest Components")
            print("3. Display Certificate Details")
            print("4. Display Permissions")
            print("5. Display Intent Filters")
            print("0. Return to Sample Submission")

            choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2', '3', '4', '5'])

            if choice == "0":
                break
            elif choice == "1":
                vt_androguard_display.display_main_activity(androguard)
            elif choice == "2":
                vt_androguard_display.display_manifest_components(androguard)
            elif choice == "3":
                vt_androguard_display.display_certificate_details(androguard)
            elif choice == "4":
                vt_androguard_display.display_permissions(androguard)
            elif choice == "5":
                vt_androguard_display.display_intent_filters(androguard)
            else:
                print("Invalid choice.")
