# DBManagement.py

import SAVED_CODE.database_functions as dbu
import database.database_performance_menu as dbpu
from utils import app_display, user_prompts

def display_database_menu():
    print(app_display.format_menu_title("Database Management Menu"))
    print(app_display.format_menu_option(1, "Test Database Connection"))
    print(app_display.format_menu_option(2, "Run Database Health Check"))
    print(app_display.format_menu_option(3, "List Database Tables"))
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
            dbu.test_database_connection()
        
        elif menu_choice == '2':
            dbu.database_health_check()
        
        elif menu_choice == '3':
            dbu.display_tables_info()
        
        elif menu_choice == '4':
            dbpu.dispay_performance()

        elif menu_choice == '5':
            dbu.empty_table('android_malware_hashes')

        input("\nPress any key to continue.")