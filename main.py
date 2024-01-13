# main.py

# Python Libraries
import os
import logging

# Custom Libraries
import static_analysis.static_analysis as static_analysis
import dynamic_analysis.dynamic_analysis as dynamic_analysis
from utils import apk_processing
from database import database_operations as db

# Configure Logging
logging.basicConfig(
    filename='logs/main.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s')

# Display Application Name
def display_app_name(app_name="DroidSecAnalytica"):
    """ Display the application name in a stylish header. """
    header_width = 40
    top_border = "╔" + "═" * (header_width - 2) + "╗"
    app_name_header = "║" + app_name.center(header_width - 2) + "║"
    bottom_border = "╚" + "═" * (header_width - 2) + "╝"
    print("\n" + top_border)
    print(app_name_header)
    print(bottom_border)

def display_menu():
    """ Display the main menu options. """
    print(format_menu_title("Main Menu", 24))
    print(format_menu_option(1, "Static Analysis"))
    print(format_menu_option(2, "Dynamic Analysis"))
    print(format_menu_option(3, "Utilities"))
    print(format_menu_option(4, "Database Management"))
    print(format_menu_option(5, "Machine Learning Model"))
    print(format_menu_option(0, "Exit"))

def format_menu_title(title, width=30):
    """ Helper function to format the menu title. """
    return f"\n{title}\n" + "=" * width

def format_menu_option(number, description):
    """ Helper function to format each menu option. """
    return f" [{number}] {description}"

def static_analysis_menu():
    print(format_menu_title("Static Analysis Menu"))
    print(format_menu_option(1, "Run Static Analysis"))
    print(format_menu_option(0, "Back to Main Menu"))

def dynamic_analysis_menu():
    print(format_menu_title("Dynamic Analysis Menu"))
    print(format_menu_option(1, "Run Dynamic Analysis"))
    print(format_menu_option(0, "Back to Main Menu"))

def utility_functions_menu():
    print(format_menu_title("Utility Functions Menu"))
    print(format_menu_option(1, "Create analysis output directory"))
    print(format_menu_option(2, "API Integration Check"))
    print(format_menu_option(3, "View Logs"))
    print(format_menu_option(0, "Back to Main Menu"))

def utility_database_menu():
    print(format_menu_title("Database Management Menu"))
    print(format_menu_option(1, "Check database connection"))
    print(format_menu_option(2, "Check database health"))
    print(format_menu_option(3, "List database tables"))
    print(format_menu_option(0, "Back to Main Menu"))

# Display APK Files
def display_apk_files():
    apk_files = [f for f in os.listdir() if f.endswith('.apk')]
    print("\nAvailable APK Files:" if apk_files else "No APK files found.")
    for i, file in enumerate(apk_files, 1):
        print(f" [{i}] {file}")
    return apk_files

def get_user_choice(prompt, valid_choices):
    """ Get and validate user choice. """
    while True:
        choice = input(prompt).strip()
        if choice in valid_choices:
            return choice
        print("Invalid choice. Please select a valid option.")

def handle_static_analysis():
    static_analysis_menu()
    sa_choice = get_user_choice("\nEnter your choice: ", ['1', '0'])
    if sa_choice == '1':
        handle_static_analysis_selection()

def handle_static_analysis_selection():
    apk_files = display_apk_files()
    if not apk_files: return
    apk_choice = get_user_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files)+1)])
    apk_path = apk_files[int(apk_choice) - 1]
    static_analysis.run_static_analysis(apk_path)

def handle_dynamic_analysis():
    dynamic_analysis_menu()
    da_choice = get_user_choice("\nEnter your choice: ", ['1', '0'])
    if da_choice == '1':
        apk_path = input("Enter the path to the APK: ").strip()
        dynamic_analysis.run_dynamic_analysis(apk_path)

def handle_utilities():
    utility_functions_menu()
    utility_choice = get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])

    if utility_choice == '1':
        apk_processing.create_output_directory()
        print("Output directory created.")

    elif utility_choice == '2':
        # Placeholder for API Integration Check
        print("API Integration Check.")

    elif utility_choice == '3':
        handle_view_logs()

def handle_database_management():
    utility_database_menu()
    utility_choice = get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])
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

def list_log_files(log_directory):
    """ List all log files in the specified directory. """
    log_files = [f for f in os.listdir(log_directory) if f.endswith('.log')]
    if not log_files:
        print("No log files found.")
        return []
    for i, file in enumerate(log_files, 1):
        print(f" [{i}] {file}")
    return log_files

def view_log_file(log_directory, log_files, choice):
    """ Display the content of the selected log file. """
    file_path = os.path.join(log_directory, log_files[choice - 1])
    with open(file_path, 'r') as file:
        print(file.read())

def handle_view_logs():
    log_directory = 'output'
    log_files = list_log_files(log_directory)
    if log_files:
        try:
            choice = int(input("Enter the number of the log file to view: "))
            if 0 < choice <= len(log_files):
                view_log_file(log_directory, log_files, choice)
            else:
                print("Invalid selection.")
        except ValueError:
            print("Please enter a valid number.")

def main_menu():
    while True:
        display_menu()
        
        choice = get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '0'])
        if choice == '1':
            handle_static_analysis()
        
        elif choice == '2':
            handle_dynamic_analysis()
        
        elif choice == '3':
            handle_utilities()
            input("\nEnter any key to continue.")

        elif choice == '4':
            handle_database_management()
            input("\nEnter any key to continue.")
        
        elif choice == '5':
            handle_machine_learning()
            input("\nEnter any key to continue.")
        
        elif choice == '0':
            print("Exiting. Goodbye!\n")
            break

def main():
    display_app_name()
    main_menu()

if __name__ == "__main__":
    main()