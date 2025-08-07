# main.py

# Standard libraries
import os
import sys
import logging
# Custom libraries
from static_analysis import static_analysis_menu
from virustotal import vt_menu
from reporting import reporting_menu
from utils import app_display, user_prompts, logging_utils
from database import db_menu, db_api_management
from permissions_analysis import process_unknown_permissions

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure Logging using logging_utils
logging_utils.setup_logger(level=logging.INFO, log_file='logs/main.log')
logger = logging_utils.get_logger(__name__)

# Main menu
def app_main_menu():
    print(app_display.format_menu_title("Main Menu", 24))
    print(app_display.format_menu_option(1, "Static Analysis"))
    print(app_display.format_menu_option(2, "VirusTotal API Analysis"))
    print(app_display.format_menu_option(3, "VirusTotal API Keys Management"))
    print(app_display.format_menu_option(4, "Report Generation"))
    print(app_display.format_menu_option(5, "Database Management"))
    print(app_display.format_menu_option(6, "Permission Management"))
    print(app_display.format_menu_option(0, "Exit"))

# Main
def main():
    while True:
        app_main_menu()
        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2', '3', '4', '5', '6'])

        try:
            if choice == '1':
                static_analysis_menu.show_menu()
            
            elif choice == '2':
                vt_menu.virustotal_menu()
            
            elif choice == '3':
                vt_api_key_menu()
            
            elif choice == '4':
                reporting_menu.report_generation_menu()
            
            elif choice == '5':
                db_menu.database_menu()

            elif choice == '6':
                process_unknown_permissions.main()
            
            elif choice == '0':
                print("\nExiting...\n")
                exit()

            user_prompts.pause_until_keypress()

        except Exception as e:
            logger.critical("An error occurred", exc_info=e)
            print("An error occurred. Please check the logs for more details.")

# VirusTotal API Key Management Menu
def vt_api_key_menu():
    while True:
        print(app_display.format_menu_title("VirusTotal API Key Management"))
        print(app_display.format_menu_option(1, "View All Keys"))
        print(app_display.format_menu_option(2, "Add New Key"))
        print(app_display.format_menu_option(3, "Delete a Key"))
        print(app_display.format_menu_option(4, "Check if API Keys need to be reset"))
        print(app_display.format_menu_option(0, "Main Menu"))

        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '0'])

        if menu_choice == '0':
            break
        elif menu_choice == '1':
            db_api_management.view_api_keys()
        elif menu_choice == '2':
            db_api_management.add_api_key()
        elif menu_choice == '3':
            db_api_management.delete_api_key_prompt()
        elif menu_choice == '4':
            db_api_management.check_and_reset_api_keys()

if __name__ == "__main__":
    try:
        app_display.display_app_name()
        app_display.display_greeting()
        main()

    except KeyboardInterrupt:
        logger.info("Program interrupted by the user. Exiting...")
        print("\nProgram interrupted by the user. Exiting...")

    except Exception as e:
        logger.critical("Critical error on startup", exc_info=e)
        print("A critical error occurred on startup. Please check the logs for more details.")
        sys.exit(1)
