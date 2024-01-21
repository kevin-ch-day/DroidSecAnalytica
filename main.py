# main.py

# Python Libraries
import os
import logging
import sys

# Import custom libraries
from static_analysis import static_analysis_menu
from dynamic_analysis import dynamic_analysis
from utils import app_display, utils_menu, user_prompts
from database import DBManagement
from machine_learning import MLManagement

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure Logging
logging.basicConfig(
    filename='logs/main.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s')

def display_menu():
    """ Display the main menu options. """
    print(app_display.format_menu_title("Main Menu", 24))
    print(app_display.format_menu_option(1, "Static Analysis"))
    print(app_display.format_menu_option(2, "Dynamic Analysis"))
    print(app_display.format_menu_option(3, "Database Management"))
    print(app_display.format_menu_option(4, "Machine Learning Model"))
    print(app_display.format_menu_option(5, "Utilities"))
    print(app_display.format_menu_option(0, "Exit"))

def main_menu():
    while True:
        display_menu()
        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '0'])

        try:
            if choice == '1':
                static_analysis_menu.static_analysis_menu()
            
            elif choice == '2':
                dynamic_analysis.dynamic_analysis_menu()
            
            elif choice == '3':
                DBManagement.database_management_menu()
            
            elif choice == '4':
                MLManagement.machine_learning_menu()
            
            elif choice == '5':
                utils_menu.utilities_menu()
            
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
        main_menu()

    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")

    except Exception as e:
        logging.error(f"Critical error on startup: {e}", exc_info=True)
        print("A critical error occurred on startup. Please check the logs for more details.")
        sys.exit(1)