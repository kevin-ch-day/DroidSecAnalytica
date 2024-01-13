# main.py

# Python Libraries
import logging

# Custom Libraries
import static_analysis.static_analysis as static_analysis
import dynamic_analysis.dynamic_analysis as dynamic_analysis
from utils import app_utils, jar_utils
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

# Sub-menu: static analysis
def static_analysis_menu():
    print(app_utils.format_menu_title("Static Analysis Menu"))
    print(app_utils.format_menu_option(1, "Decompile APK"))
    print(app_utils.format_menu_option(2, "Create APK Record"))
    print(app_utils.format_menu_option(3, "Static Analysis I."))
    print(app_utils.format_menu_option(4, "Metadata Analysis"))
    print(app_utils.format_menu_option(5, "Permissions Analysis"))
    print(app_utils.format_menu_option(6, "Export Static Analysis Data"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def dynamic_analysis_menu():
    print(app_utils.format_menu_title("Dynamic Analysis Menu"))
    print(app_utils.format_menu_option(1, "Run Dynamic Analysis"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def utility_functions_menu():
    print(app_utils.format_menu_title("Utility Functions Menu"))
    print(app_utils.format_menu_option(1, "API Integration Check"))
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
    sa_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '0'])
    
    if sa_choice == '1':
        handle_decompile_apk()
    
    elif sa_choice == '2':
        handle_create_apk_record()
    
    elif sa_choice == '3':
        run_static_analysis()
    
    elif sa_choice == '4':
        handle_metadata_analysis()
    
    elif sa_choice == '5':
        handle_permissions_analysis()
    
    elif sa_choice == '6':
        handle_export_static_analysis_data()
    
    elif sa_choice == '0':
        return

# Handling creation of APK record
def handle_create_apk_record():
    print("Creating APK record...")

# Handling metadata analysis
def handle_metadata_analysis():
    print("Performing metadata analysis...")

# Handling permissions analysis
def handle_permissions_analysis():
    print("Performing permissions analysis...")

# Handling export of static analysis data
def handle_export_static_analysis_data():
    print("Exporting static analysis data...")

def run_static_analysis():
    apk_path = android_apk_selection()
    static_analysis.run_static_analysis(apk_path)

def handle_decompile_apk():
    apk_path = android_apk_selection()
    static_analysis.decompile_apk(apk_path)

def android_apk_selection():
    apk_files = app_utils.display_apk_files()
    if not apk_files: return
    apk_choice = app_utils.get_user_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files)+1)])
    return apk_files[int(apk_choice) - 1]

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
        print("API Integration Check.")

    elif utility_choice == '0':
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