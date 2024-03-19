# main.py

# Standard libraries
import os
import sys
import logging

# Custom libraries
from static_analysis import static_analysis_menu
from virustotal import vt_menu
from dynamic_analysis import dynamic_analysis
from reporting import reporting
from utils import app_display, user_prompts
from database import db_menu
from utils import logging_utils

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure Logging using logging_utils
logging_utils.setup_logger(level=logging.INFO, log_file='logs/main.log')

# Main menu
def main_menu():
    print(app_display.format_menu_title("Main Menu", 24))
    print(app_display.format_menu_option(1, "Static Analysis"))
    print(app_display.format_menu_option(2, "Dynamic Analysis"))
    print(app_display.format_menu_option(3, "VirusTotal Analysis"))
    print(app_display.format_menu_option(4, "Report Generation"))
    print(app_display.format_menu_option(5, "Database Management"))
    print(app_display.format_menu_option(0, "Exit"))

# Main
def main():
    while True:
        main_menu()
        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2', '3', '4', '5'])

        try:
            if choice == '1':
                static_analysis_menu.show_menu()
            
            elif choice == '2':
                dynamic_analysis.dynamic_menu()
            
            elif choice == '3':
                vt_menu.virustotal_menu()
            
            elif choice == '4':
                reporting.report_menu()
            
            elif choice == '5':
                db_menu.database_menu()
            
            elif choice == '0':
                print("\nExiting. Goodbye!\n")
                break

            user_prompts.pause_until_keypress()

        except Exception as e:
            logging_utils.log_critical(f"An error occurred: {e}", exc_info=True)
            print("An error occurred. Please check the logs for more details.")

if __name__ == "__main__":
    try:
        app_display.display_app_name()
        app_display.display_greeting()
        main()

    except KeyboardInterrupt:
        logging_utils.log_info("Program interrupted by the user. Exiting...")
        print("\nProgram interrupted by the user. Exiting...")

    except Exception as e:
        logging_utils.log_critical(f"Critical error on startup: {e}", exc_info=True)
        print("A critical error occurred on startup. Please check the logs for more details.")
        sys.exit(1)