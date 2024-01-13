# main.py

# Python Libraries
import os
import logging

# Custom Libraries
import static_analysis.static_analysis as static_analysis
import dynamic_analysis.dynamic_analysis as dynamic_analysis
from utils import apk_processing, app_utils
from database import database_operations as db

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

def static_analysis_menu():
    print(app_utils.format_menu_title("Static Analysis Menu"))
    print(app_utils.format_menu_option(1, "Run Static Analysis"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def dynamic_analysis_menu():
    print(app_utils.format_menu_title("Dynamic Analysis Menu"))
    print(app_utils.format_menu_option(1, "Run Dynamic Analysis"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def utility_functions_menu():
    print(app_utils.format_menu_title("Utility Functions Menu"))
    print(app_utils.format_menu_option(1, "Create analysis output directory"))
    print(app_utils.format_menu_option(2, "API Integration Check"))
    print(app_utils.format_menu_option(3, "View Logs"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def utility_database_menu():
    print(app_utils.format_menu_title("Database Management Menu"))
    print(app_utils.format_menu_option(1, "Check database connection"))
    print(app_utils.format_menu_option(2, "Check database health"))
    print(app_utils.format_menu_option(3, "List database tables"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def handle_static_analysis():
    static_analysis_menu()
    sa_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '0'])
    if sa_choice == '1':
        handle_static_analysis_selection()

def handle_static_analysis_selection():
    apk_files = app_utils.display_apk_files()
    if not apk_files: return
    apk_choice = app_utils.get_user_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files)+1)])
    apk_path = apk_files[int(apk_choice) - 1]
    static_analysis.run_static_analysis(apk_path)

def handle_dynamic_analysis():
    dynamic_analysis_menu()
    da_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '0'])
    if da_choice == '1':
        apk_path = input("Enter the path to the APK: ").strip()
        dynamic_analysis.run_dynamic_analysis(apk_path)

def handle_utilities():
    utility_functions_menu()
    utility_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])

    if utility_choice == '1':
        apk_processing.create_output_directory()
        print("Output directory created.")

    elif utility_choice == '2':
        # Placeholder for API Integration Check
        print("API Integration Check.")

    elif utility_choice == '3':
        app_utils.handle_view_logs()

def handle_database_management():
    utility_database_menu()
    utility_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])
    if utility_choice == '1':
        db.test_database_connection()
    
    elif utility_choice == '2':
        db.database_health_check()
    
    elif utility_choice == '3':
        conn = db.connect_to_database()
        db.list_tables(conn)

def handle_machine_learning():
    # Placeholder for machine learning models menu
    print("Machine Learning Models - Feature Coming Soon")

def main_menu():
    while True:
        display_menu()

        choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '0'])

        if choice == '1':
            handle_static_analysis()
        
        elif choice == '2':
            handle_dynamic_analysis()
        
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

def main():
    app_utils.display_app_name()
    main_menu()

if __name__ == "__main__":
    main()
