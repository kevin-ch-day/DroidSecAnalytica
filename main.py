# main.py

# Python libraries
import os
import shutil
import logging

# Custom libraries
import static_analysis.static_analysis as static_analysis
import dynamic_analysis.dynamic_analysis as dynamic_analysis
from utils import apk_processing, ml_model
from database import database_operations as db

# Configure logging
logging.basicConfig(
        filename='logs\main.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s: %(message)s')

# Display menu
def display_menu(app_name="DroidSecAnalytica"):
    """
    Display the main menu options.

    Args:
        app_name (str): The name of the application.
    """
    print(f"\n Main Menu")
    print("=" * 24)
    print(" 1. Static Analysis")
    print(" 2. Dynamic Analysis")
    print(" 3. Utility Functions")
    print(" 4. Database Operations")
    print(" 5. Change Model")
    print(" 6. Load Model")
    print(" 0. Exit")
    print("=" * 24)

# Display application name
def display_app_name(app_name="DroidSecAnalytica"):
    """
    Display the name of the application in a stylish header.

    Args:
        app_name (str): The name of the application.
    """
    app_name_length = len(app_name)
    header_width = 40  # Adjust the width as needed

    # Create the top border
    top_border = "╔" + "═" * (header_width - 2) + "╗"
    
    # Create the centered header with the application name
    app_name_header = "║" + app_name.center(header_width - 2) + "║"
    
    # Create the bottom border
    bottom_border = "╚" + "═" * (header_width - 2) + "╝"

    # Print the header
    print("\n" + top_border)
    print(app_name_header)
    print(bottom_border)

# Static analysis menu
def static_analysis_menu():
    print("\n Static Analysis Menu")
    print("=" * 24)
    print(" 1. Static Analysis Alpha")
    print(" 0. Back to Main Menu")

# Dynamic analysis menu
def dynamic_analysis_menu():
    print("\n Dynamic Analysis Menu")
    print(" 1. Dynamic Alpha")
    print(" 0. Back to Main Menu")

# Utility functions menu
def utility_functions_menu():
    print("\n Utility Functions Menu")
    print("=" * 24)
    print(" 1. Create Output Directory")
    print(" 2. Save Results")
    print(" 0. Back to Main Menu")

# Database operations menu
def database_operations_menu():
    print("\n Database Operations Menu")
    print("=" * 24)
    print(" 1. Check database connection")
    print(" 0. Back to Main Menu")

# Exit the application
def exit_app():
    try:
        while True:
            confirmation = input("\nAre you sure you want to exit? (yes/no): ").strip().lower()
            if confirmation == 'yes':
                print("\nExiting. Goodbye!")
                exit()
            
            elif confirmation == 'no':
                return  # Return to the main menu
            
            else:
                print("Please enter 'yes' or 'no'.")

    except SystemExit:
        pass  # Catch the exit call and continue gracefully

def display_apk_files():
    directory = os.getcwd()
    apk_files = [file for file in os.listdir(directory) if file.endswith('.apk')]

    if not apk_files:
        print("No APK files found in the current directory.")
        return None

    print("\nAvaiable APK files")
    for cnt, file in enumerate(apk_files, start=1):
        print(f" [{cnt}] {file}")
    print(" [0] Exit")

    while True:
        try:
            choice = int(input("\nSelect an APK option: "))
            if choice == 0:
                print("Exiting selection.")
                return None
            elif 1 <= choice <= len(apk_files):
                selected_apk = apk_files[choice - 1]
                selected_path = os.path.join(directory, selected_apk)
                return selected_path
            else:
                print("Invalid selection. Please select a number or 0 to exit.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

# Main
def main():
    while True:
        display_app_name()  # Display the name of the application
        display_menu()
        choice = input("\nEnter your choice: ")

        # Exit
        if choice == '0':
            exit_app()

        # Static analysis
        elif choice == '1':
            static_analysis_menu()
            static_choice = input("\nEnter your choice: ")
            if static_choice == "0":
                pass

            elif static_choice == "1":
                apk_path = display_apk_files()
                if not os.path.exists(apk_path):
                    print("Invalid file path. Please provide a valid APK file path.")
                else:
                    print("\nRunning static analysis on: " + os.path.basename(apk_path))
                    static_analysis.run_static_analysis(apk_path)

            input("\nPress Enter to continue...")

        # Dynamic analysis
        elif choice == '2':
            dynamic_analysis_menu()
            dynamic_choice = input("\nEnter your choice: ")
            if dynamic_choice == '1':
                print("\nDynamic Analysis")
                apk_path = input("Enter the path to the APK file for dynamic analysis: ")
                if not os.path.exists(apk_path):
                    print("Invalid file path. Please provide a valid APK file path.")
                    continue
                dynamic_analysis.run_dynamic_analysis(apk_path)
                input("\nPress Enter to continue...")
            
            else:
                print("Invalid choice. Please select a valid option.")
                continue

        # Utility functions
        elif choice == '3':
            utility_functions_menu()
            utility_choice = input("\nEnter your choice: ")

            # Create Output Directory
            if utility_choice == '1':
                apk_processing.create_output_directory()
                print("Output directory created successfully.")
                input("\nPress Enter to continue...")

            # Save Results
            elif utility_choice == '2':
                apk_path = input("Enter APK path: ")
                result_data = {
                    "package_name": "com.example",
                    "permissions": ["permission1", "permission2"]
                }
                apk_processing.save_results(apk_path, result_data)
                print("Results saved successfully.")
                input("\nPress Enter to continue...")

            else:
                print("Invalid choice. Please select a valid option.")
                continue

        # Database operations 
        elif choice == '4':
            database_operations_menu()
            db_choice = input("\nEnter your choice: ")
            # exit
            if db_choice == '0':
                return
            # test connection
            elif db_choice == '1':
                db.test_connection()
            # invalid choice
            else:
                print("Invalid choice. Please select a valid option.")
                continue

        # Choice model
        elif choice == '5':
            ml_model.change_model()
        
        # Load model
        elif choice == '6':
            model_path = input("Enter the path to the model file: ")
            model = ml_model.load_model(model_path)
            # Use the loaded model as needed
        
        # Invalid
        else:
            print("Invalid choice. Please select a valid option.")

# CLI
if __name__ == "__main__":
    main()
