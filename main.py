# main.py

# Python libraries
import os
import logging

# Custom libraries
import static_analysis.static_analysis as static_analysis
import dynamic_analysis.dynamic_analysis as dynamic_analysis
from utils import apk_processing, ml_model
from database import database_main

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
    print(" 1. Run Static Analysis")
    print(" 0. Back to Main Menu")

# Dynamic analysis menu
def dynamic_analysis_menu():
    print("\n Dynamic Analysis Menu")
    print(" 1. Run Dynamic Analysis")
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
    print(" 1. Connect to Database")
    print(" 2. Store Analysis Result")
    print(" 3. Retrieve Data")
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
                print(os.getcwd())
                apk_path = input("Enter the path to the APK file for static analysis: ")
                if not os.path.exists(apk_path):
                    print("Invalid file path. Please provide a valid APK file path.")
                else:
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
            if db_choice == '1':
                db_path = input("Enter database path: ")
                db = database_main.connect_to_database(db_path)
                if db:
                    print("Connected to the database successfully.")
                else:
                    print("Error connecting to the database.")
                input("\nPress Enter to continue...")

            elif db_choice == '2':
                if not 'db' in locals():
                    print("Please connect to the database first.")
                    continue
                apk_name = input("Enter APK name: ")
                analysis_result = {"apk_name": apk_name, "analysis_type": "static", "result": "success"}
                database_main.store_analysis_result(db, analysis_result)
                print("Analysis result stored in the database.")
                input("\nPress Enter to continue...")

            elif db_choice == '3':
                if not 'db' in locals():
                    print("Please connect to the database first.")
                    continue
                apk_name = input("Enter APK name: ")
                data = database_main.retrieve_data(db, apk_name)
                if data:
                    print("Retrieved data:")
                    print(data)
                else:
                    print("No data found in the database.")
                input("\nPress Enter to continue...")

            elif db_choice == '4':
                continue

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
