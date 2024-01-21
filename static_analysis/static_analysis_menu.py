# static_analysis_menu.py

# Standard library imports
import logging

# Local application imports
from utils import app_utils, app_display, user_prompts
from . import static_analysis

# Configure logging
LOG_FILE_PATH = 'logs/static_analysis.log'
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

# Display the static analysis menu and handle user interaction.
def static_analysis_menu():
    while True:
        display_menu()
        menu_choice =  user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(11)])
        
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

# Display the static analysis menu options
def display_menu():
    print(app_display.format_menu_title("Static Analysis Menu"))
    for i in range(1, 11):
        print(app_display.format_menu_option(i, get_menu_option_text(i)))
    print(app_display.format_menu_option(0, "Return to Main Menu"))

# Get menu option text based on the option number
def get_menu_option_text(option_number):
    menu_options = [
        "Check if sample has been previously analyzed",
        "Decompile APK file for detailed analysis",
        "In-depth static analysis on APK",
        "In-depth static analysis on Hash",
        "Static APK Analysis II",
        "Permissions Analysis",
        "Display available APK Files",
        "Display APK File Hashes",
        "Perform VirusTotal.com APK Analysis",
        "Perform VirusTotal.com Hash IOC Analysis"
    ]
    return menu_options[option_number - 1]