# main.py

import os
import logging
import sys

# Import custom libraries
from static_analysis import static_analysis
from dynamic_analysis import dynamic_analysis
from reporting import reporting
from utils import app_display, utils_menu, user_prompts
from database import database_menu

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure Logging
logging.basicConfig(
    filename='logs/main.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s')

def main_menu():
    print(app_display.format_menu_title("Main Menu", 24))
    print(app_display.format_menu_option(1, "Static Analysis"))
    print(app_display.format_menu_option(2, "Dynamic Analysis"))
    print(app_display.format_menu_option(3, "Report Generation"))
    print(app_display.format_menu_option(4, "Database Management"))
    print(app_display.format_menu_option(5, "Utilities"))
    print(app_display.format_menu_option(0, "Exit"))

def main():
    while True:
        main_menu()
        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '0'])

        try:
            if choice == '1':
                static_analysis.static_menu()
            
            elif choice == '2':
                dynamic_analysis.dynamic_menu()
            
            elif choice == '3':
                reporting.report_menu()
            
            elif choice == '4':
                database_menu.database_menu()
            
            elif choice == '5':
                utils_menu.display_app_utils()
            
            elif choice == '0':
                print("Exiting. Goodbye!\n")
                break

            user_prompts.pause_until_keypress()

        except Exception as e:
            logging.error(f"An error occurred: {e}", exc_info=True)
            print("An error occurred. Please check the logs for more details.")

if __name__ == "__main__":
    try:
        app_display.display_app_name()
        app_display.display_greeting()
        main()

    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")

    except Exception as e:
        logging.error(f"Critical error on startup: {e}", exc_info=True)
        print("A critical error occurred on startup. Please check the logs for more details.")
        sys.exit(1)