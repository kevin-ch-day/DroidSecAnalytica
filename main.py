# Python libraries
import os

# Custom libraries
from static_analysis.static_main import execute_static_analysis
from dynamic_analysis.dynamic_main import execute_dynamic_analysis
from utils.utils_main import *

# Main function
def main():
    while True:
        print("\nDroidSecAnalytica\n")
        print("1. Static Analysis")
        print("2. Dynamic Analysis")
        print("0. Exit")
        
        choice = input("\nEnter your choice: ")

        if choice == '0':
            print("\nExiting DroidSecAnalytica. Goodbye!")
            exit()
        
        elif choice == '1':
            print("\nStatic Analysis")
            #apk_path = input("Enter the path to the APK file for static analysis: ")
            apk_path = 'SharkBot-Nov-2021.apk'
            # Validate the file path
            if not os.path.exists(apk_path):
                print("Invalid file path. Please provide a valid APK file path.")
                continue
            
            # Call the static analysis function
            execute_static_analysis(apk_path)
            input("\nPress Enter to continue...")

        elif choice == '2':
            print("\nDynamic Analysis")
            apk_path = input("Enter the path to the APK file for dynamic analysis: ")
            
            # Validate the file path
            if not os.path.exists(apk_path):
                print("Invalid file path. Please provide a valid APK file path.")
                continue
            
            # Call the dynamic analysis function
            execute_dynamic_analysis(apk_path)
            input("\nPress Enter to continue...")

        else:
            print("Invalid choice. Please select a valid option.")

# CLI
if __name__ == "__main__":
    main()