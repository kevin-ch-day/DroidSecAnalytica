import os
import logging
from static_analysis.static_main import execute_static_analysis
from dynamic_analysis.dynamic_main import execute_dynamic_analysis
from utils.utils_main import create_output_directory, save_results
from database.database_main import connect_to_database, store_analysis_result, retrieve_data

# Configure logging
logging.basicConfig(filename='droidsecanalytica.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def display_menu():
    print("\nDroidSecAnalytica")
    print("1. Static Analysis")
    print("2. Dynamic Analysis")
    print("3. Utility Functions")
    print("4. Database Operations")
    print("0. Exit")

def static_analysis_menu():
    print("\nStatic Analysis Menu")
    print("1. Perform Static Analysis")
    print("2. Back to Main Menu")

def dynamic_analysis_menu():
    print("\nDynamic Analysis Menu")
    print("1. Perform Dynamic Analysis")
    print("2. Back to Main Menu")

def utility_functions_menu():
    print("\nUtility Functions Menu")
    print("1. Create Output Directory")
    print("2. Save Results")
    print("3. Back to Main Menu")

def database_operations_menu():
    print("\nDatabase Operations Menu")
    print("1. Connect to Database")
    print("2. Store Analysis Result")
    print("3. Retrieve Data")
    print("4. Back to Main Menu")

def main():
    while True:
        display_menu()
        choice = input("\nEnter your choice: ")

        if choice == '0':
            print("\nExiting DroidSecAnalytica. Goodbye!")
            exit()

        elif choice == '1':
            static_analysis_menu()
            static_choice = input("Enter your choice: ")
            if static_choice == '1':
                print("\nStatic Analysis")
                apk_path = input("Enter the path to the APK file for static analysis: ")
                if not os.path.exists(apk_path):
                    print("Invalid file path. Please provide a valid APK file path.")
                    continue
                execute_static_analysis(apk_path)
                input("\nPress Enter to continue...")
            elif static_choice == '2':
                continue
            else:
                print("Invalid choice. Please select a valid option.")
                continue

        elif choice == '2':
            dynamic_analysis_menu()
            dynamic_choice = input("Enter your choice: ")
            if dynamic_choice == '1':
                print("\nDynamic Analysis")
                apk_path = input("Enter the path to the APK file for dynamic analysis: ")
                if not os.path.exists(apk_path):
                    print("Invalid file path. Please provide a valid APK file path.")
                    continue
                execute_dynamic_analysis(apk_path)
                input("\nPress Enter to continue...")
            elif dynamic_choice == '2':
                continue
            else:
                print("Invalid choice. Please select a valid option.")
                continue

        elif choice == '3':
            utility_functions_menu()
            utility_choice = input("Enter your choice: ")
            if utility_choice == '1':
                create_output_directory()
                print("Output directory created successfully.")
                input("\nPress Enter to continue...")
            elif utility_choice == '2':
                apk_path = input("Enter APK path: ")
                result_data = {
                    "package_name": "com.example",
                    "permissions": ["permission1", "permission2"]
                }
                save_results(apk_path, result_data)
                print("Results saved successfully.")
                input("\nPress Enter to continue...")
            elif utility_choice == '3':
                continue
            else:
                print("Invalid choice. Please select a valid option.")
                continue

        elif choice == '4':
            database_operations_menu()
            db_choice = input("Enter your choice: ")
            if db_choice == '1':
                db_path = input("Enter database path: ")
                db = connect_to_database(db_path)
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
                store_analysis_result(db, analysis_result)
                print("Analysis result stored in the database.")
                input("\nPress Enter to continue...")

            elif db_choice == '3':
                if not 'db' in locals():
                    print("Please connect to the database first.")
                    continue
                apk_name = input("Enter APK name: ")
                data = retrieve_data(db, apk_name)
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

        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
