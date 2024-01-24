# database_menu.py

from utils import app_display
from utils import user_prompts
from utils import app_utils
from utils import logging_utils
from . import database_manager as dbConnect

# Database management menu
def database_menu():
    while True:
        print(app_display.format_menu_title("Database Management Menu"))
        print(app_display.format_menu_option(1, "Test Database Connection"))
        print(app_display.format_menu_option(2, "Load Android Malware Hashes"))
        print(app_display.format_menu_option(2, "Display Table Information"))
        print(app_display.format_menu_option(3, "Show Query Statistics"))
        print(app_display.format_menu_option(4, "Display Disk Usage"))
        print(app_display.format_menu_option(5, "Show Thread Information"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))

        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '0'])
        if menu_choice == '0':
            return
        
        elif menu_choice == '1':
            dbConnect.test_database_connection()

        elif menu_choice == '2':
            load_android_hashes()

        elif menu_choice == '3':
            table_data = dbConnect.database_tables_info()
            app_display.display_tables_info(table_data)

        elif menu_choice == '4':
            query_stats = dbConnect.get_query_statistics()
            app_display.display_query_statistics(query_stats)

        elif menu_choice == '5':
            disk_usage = dbConnect.get_disk_usage()
            app_display.display_disk_usage(disk_usage)

        elif menu_choice == '6':
            thread_info = dbConnect.get_thread_information()
            app_display.display_thread_information(thread_info)

        input("\nPress any key to continue.")

def show_query_statistics(conn):
    try:
        query_stats = dbConnect.get_query_statistics(conn)
        if query_stats:
            app_utils.format_query_statistics(query_stats)
        else:
            print("Query statistics are not available.")
            logging_utils.log_warning("Query statistics are not available.")
    except Exception as e:
        logging_utils.log_error("Error displaying query statistics", e)

def load_android_hashes():
    try:
        load_data.load_android_malware_hash_data()
    except Exception as e:
        print(f"Error loading Android malware hashes: {e}")