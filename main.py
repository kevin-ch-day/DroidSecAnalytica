# main.py

# Python Libraries
import logging

# Custom Libraries
from static_analysis import static_analysis
from dynamic_analysis import dynamic_analysis
from utils import app_utils, app_display, utils_menu
from database import DBManagement
from machine_learning import MLManagement
from virustotal import vt_analysis

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
    print(app_display.format_menu_option(6, "VirusTotal API Analysis"))
    print(app_display.format_menu_option(0, "Exit"))

def main_menu():
    while True:
        display_menu()
        choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '0'])

        if choice == '1':
            static_analysis.handle_static_analysis()
        
        elif choice == '2':
            dynamic_analysis.handle_dynamic_analysis()

        elif choice == '3':
            DBManagement.handle_database_management()

        elif choice == '4':
            MLManagement.handle_machine_learning()

        elif choice == '5':
            utils_menu.handle_utilities()

        elif choice == '5':
            vt_analysis.virustotal_menu()

        elif choice == '0':
            print("Exiting. Goodbye!\n")
            break

        input("\nEnter any key to return to Main Menu.")

if __name__ == "__main__":
    app_display.display_app_name()
    main_menu()