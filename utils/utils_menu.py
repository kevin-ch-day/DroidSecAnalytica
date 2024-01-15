# utils_menu.py

from . import app_display
from . import app_utils
from . import load_data
from . import export_data

def utility_functions_menu():
    print(app_display.format_menu_title("Utility Functions"))
    print(app_display.format_menu_option(1, "API Integration Check"))
    print(app_display.format_menu_option(2, "Load Android Malware Hashes"))
    print(app_display.format_menu_option(3, "Export Malware Hash Table Data"))
    print(app_display.format_menu_option(0, "Back to Main Menu"))

def handle_utilities():
    utility_functions_menu()
    choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])
    if choice == '0':
        return
    
    elif choice == '1':
        # place holder
        print("API Integration Check.")

    elif choice == '2':
        load_data.loadAndroidHashData()
        
    elif choice == '3':
        export_data.hash_data_txt()
        export_data.hash_data_excel()
        export_data.hash_data_csv()
        export_data.comprehensive_analysis_report()