# static_analysis_menu.py

# Standard library imports
import logging

# Local application imports
from utils import app_utils, app_display, user_prompts
import static_analysis

# Configure logging
LOG_FILE_PATH = 'logs/static_analysis.log'
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

# Display the static analysis menu and handle user interaction.
def display_static_analysis_menu():
    while True:
        print(app_display.format_menu_title("Static Analysis Menu"))
        print(app_display.format_menu_option(1, "Check if sample has been previously analyzed"))
        print(app_display.format_menu_option(2, "Decompile APK file for detailed analysis"))
        print(app_display.format_menu_option(3, "In-depth static analysis on APK"))
        print(app_display.format_menu_option(4, "In-depth static analysis on Hash"))
        print(app_display.format_menu_option(5, "Static APK Analysis II"))
        print(app_display.format_menu_option(6, "Permissions Analysis"))
        print(app_display.format_menu_option(7, "Display available APK Files"))
        print(app_display.format_menu_option(8, "Display APK File Hashes"))
        print(app_display.format_menu_option(9, "Perform VirusTotal.com APK Analysis"))
        print(app_display.format_menu_option(10, "Perform VirusTotal.com Hash IOC Analysis"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))

        # Collecting user's choice
        menu_choice = user_prompts.prompt_user_menu_choice("\nEnter your choice: ", [str(i) for i in range(11)])

        # Handle user's choice
        if menu_choice == '1':
            static_analysis.handle_sample_check()
        elif menu_choice == '2':
            static_analysis.handle_apk_decompilation()
        elif menu_choice == '3':
            static_analysis.handle_indepth_apk_analysis()
        elif menu_choice == '4':
            static_analysis.handle_indepth_hash_analysis()
        elif menu_choice == '5':
            static_analysis.handle_static_apk_analysis_beta()
        elif menu_choice == '6':
            static_analysis.handle_permissions_analysis()
        elif menu_choice == '7':
            app_utils.display_apk_files()
        elif menu_choice == '8':
            static_analysis.display_apk_file_hashes()
        elif menu_choice == '9':
            static_analysis.perform_virustotal_apk_analysis()
        elif menu_choice == '10':
            static_analysis.perform_virustotal_hash_analysis()
        elif menu_choice == '0':
            break
        else:
            print("Invalid option. Please try again.")

        user_prompts.pause_until_keypress()

if __name__ == "__main__":
    display_static_analysis_menu()
