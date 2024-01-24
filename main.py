import os
import sys

# Import custom libraries
from static_analysis import static_analysis
from dynamic_analysis import dynamic_analysis
from reporting import reporting
from utils import app_display, user_prompts
from database import DBMenu
from utils import logging_utils

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure Logging using logging_utils
logging_utils.configure_logging(filename='logs/main.log', level=logging_utils.INFO)

def main_menu():
    print(app_display.format_menu_title("Main Menu", 24))
    print(app_display.format_menu_option(1, "Static Analysis"))
    print(app_display.format_menu_option(2, "Dynamic Analysis"))
    print(app_display.format_menu_option(3, "Report Generation"))
    print(app_display.format_menu_option(4, "Database Management"))
    print(app_display.format_menu_option(5, "Check Virustotal API Key"))
    print(app_display.format_menu_option(6, "Exit"))

def main():
    while True:
        main_menu()
        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6'])

        try:
            if choice == '1':
                static_analysis.static_menu()
            
            elif choice == '2':
                dynamic_analysis.dynamic_menu()
            
            elif choice == '3':
                reporting.report_menu()
            
            elif choice == '4':
                DBMenu.database_menu()
            
            elif choice == '5':
                handle_api_integration()
            
            elif choice == '6':
                logging_utils.log_info("Exiting the program.")
                print("Exiting. Goodbye!\n")
                break

            user_prompts.pause_until_keypress()

        except Exception as e:
            logging_utils.log_error(f"An error occurred: {e}", exc_info=True)
            print("An error occurred. Please check the logs for more details.")

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

if __name__ == "__main__":
    try:
        app_display.display_app_name()
        app_display.display_greeting()
        main()

    except KeyboardInterrupt:
        logging_utils.log_info("Program interrupted by the user. Exiting...")
        print("\nProgram interrupted by the user. Exiting...")

    except Exception as e:
        logging_utils.log_error(f"Critical error on startup: {e}", exc_info=True)
        print("A critical error occurred on startup. Please check the logs for more details.")
        sys.exit(1)
