# main.py

# Python Libraries
import logging

# Custom Libraries
import static_analysis.static_analysis as static_analysis
import dynamic_analysis.dynamic_analysis as dynamic_analysis
from utils import app_utils
from database import database_core, database_functions

# Configure Logging
logging.basicConfig(
    filename='logs/main.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s')

def display_menu():
    """ Display the main menu options. """
    print(app_utils.format_menu_title("Main Menu", 24))
    print(app_utils.format_menu_option(1, "Static Analysis"))
    print(app_utils.format_menu_option(2, "Dynamic Analysis"))
    print(app_utils.format_menu_option(3, "Utilities"))
    print(app_utils.format_menu_option(4, "Database Management"))
    print(app_utils.format_menu_option(5, "Machine Learning Model"))
    print(app_utils.format_menu_option(0, "Exit"))

def utility_functions_menu():
    print(app_utils.format_menu_title("Utility Functions Menu"))
    print(app_utils.format_menu_option(1, "API Integration Check"))
    print(app_utils.format_menu_option(2, "View Logs"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def utility_database_menu():
    print(app_utils.format_menu_title("Database Management Menu"))
    print(app_utils.format_menu_option(1, "Check database connection"))
    print(app_utils.format_menu_option(2, "Check database health"))
    print(app_utils.format_menu_option(3, "List database tables"))
    print(app_utils.format_menu_option(4, "Clear the Android hash Table"))
    print(app_utils.format_menu_option(5, "Export Android hash data"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def handle_utilities():
    utility_functions_menu()
    utility_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])
    if utility_choice == '0':
        return
    
    elif utility_choice == '1':
        print("API Integration Check.")

    elif utility_choice == '2':
        print("View logs.")
        app_utils.handle_view_logs()

def handle_machine_learning():
    # Placeholder for machine learning models menu
    print("Machine Learning Models - Feature Coming Soon")

def main_menu():
    while True:
        display_menu()

        choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '0'])

        if choice == '1':
            static_analysis.handle_static_analysis()
        
        elif choice == '2':
            dynamic_analysis.handle_dynamic_analysis()
        
        elif choice == '3':
            handle_utilities()

        elif choice == '4':
            handle_database_management()

        elif choice == '5':
            handle_machine_learning()

        elif choice == '0':
            if input("Are you sure you want to exit? (y/n): ").lower() == 'y':
                print("Exiting. Goodbye!\n")
                break

        input("\nEnter any key to return to Main Menu.")

if __name__ == "__main__":
    app_utils.display_app_name()
    main_menu()