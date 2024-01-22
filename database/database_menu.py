# DBManagement.py

from . import database_manager as db_manager
from . import database_performance_utils as db_perform_utils
from . import database_performance_menu as db_perform_menu
from utils import app_display, user_prompts

def display_database_menu():
    print(app_display.format_menu_title("Database Management Menu"))
    print(app_display.format_menu_option(1, "Test Database Connection"))
    print(app_display.format_menu_option(2, "List Database Tables"))
    print(app_display.format_menu_option(3, "Run Database Health Check"))
    print(app_display.format_menu_option(4, "View Database Performance Metrics"))
    print(app_display.format_menu_option(5, "Clear Android Malware Hash Table"))
    print(app_display.format_menu_option(0, "Return to Main Menu"))

def database_management_menu():
    while True:
        display_database_menu()
        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5','0'])

        if menu_choice == '0':
            return
        
        elif menu_choice == '1':
            db_manager.test_database_connection()
        
        elif menu_choice == '2':
            db_manager.display_tables_info()

        elif menu_choice == '3':
            db_perform_utils.database_health_check()
        
        elif menu_choice == '4':
            db_perform_menu.dispay_performance()

        elif menu_choice == '5':
            db_manager.empty_table('android_malware_hashes')

        input("\nPress any key to continue.")