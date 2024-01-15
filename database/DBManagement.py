import database.DBUtils as dbu
import database.DBPerformance as dbpu
from utils import app_utils, app_display

def database_management_menu():
    print(app_display.format_menu_title("Database Management Menu"))
    print(app_display.format_menu_option(1, "Test Database Connection"))
    print(app_display.format_menu_option(2, "Run Database Health Check"))
    print(app_display.format_menu_option(3, "List Database Tables"))
    print(app_display.format_menu_option(4, "View Database Performance Metrics"))
    print(app_display.format_menu_option(5, "Clear Android Malware Hash Table"))
    print(app_display.format_menu_option(0, "Return to Main Menu"))

def handle_database_management():
    while True:
        database_management_menu()
        utility_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5','0'])
        print()

        if utility_choice == '0':
            return
        
        elif utility_choice == '1':
            dbu.test_database_connection()
        
        elif utility_choice == '2':
            dbu.database_health_check()
        
        elif utility_choice == '3':
            dbu.display_tables_info()
        
        elif utility_choice == '4':
            dbpu.dispay_performance()

        elif utility_choice == '5':
            dbu.empty_table('android_malware_hashes')

        input("\nPress any key to continue.")