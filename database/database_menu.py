# database_menu.py

from . import database_manager as db_manager
from . import database_utils_1 as utils
from utils import app_display, user_prompts

def display_database_menu():
    print(app_display.format_menu_title("Database Management Menu"))
    print(app_display.format_menu_option(1, "Test Database Connection"))
    print(app_display.format_menu_option(2, "List Database Tables"))
    print(app_display.format_menu_option(3, "Run Database Health Check"))
    print(app_display.format_menu_option(4, "Clear Android Malware Hash Table"))
    print(app_display.format_menu_option(5, "Query Count"))
    print(app_display.format_menu_option(6, "Slow Queries"))
    print(app_display.format_menu_option(7, "Memory Usage"))
    print(app_display.format_menu_option(8, "Thread Information"))
    print(app_display.format_menu_option(0, "Return to Main Menu"))

def database_management_menu():
    while True:
        display_database_menu()
        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '7', '8', '0'])

        if menu_choice == '0':
            return
        
        elif menu_choice == '1':
            db_manager.test_database_connection()
        
        elif menu_choice == '2':
            db_manager.display_tables_info()

        elif menu_choice == '3':
            utils.database_health_check()

        elif menu_choice == '4':
            db_manager.empty_table('android_malware_hashes')

        elif menu_choice == '5':
            utils.show_query_count()
            
        elif menu_choice == '6':
            utils.show_slow_queries()
            
        elif menu_choice == '7':
            utils.show_memory_usage()
            
        elif menu_choice == '8':
            utils.show_thread_info()

        input("\nPress any key to continue.")
