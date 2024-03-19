# db_menu.py

from utils import app_display, user_prompts, logging_utils
from . import db_conn, db_info, db_management

# Database management menu
def database_menu():
    while True:
        print(app_display.format_menu_title("Database Management Menu"))
        print(app_display.format_menu_option(1, "Test Database Connection"))
        print(app_display.format_menu_option(2, "Display Table Information"))
        print(app_display.format_menu_option(3, "Show Query Statistics"))
        print(app_display.format_menu_option(4, "Display Disk Usage"))
        print(app_display.format_menu_option(5, "Show Thread Information"))
        print(app_display.format_menu_option(6, "Clear analysis tables"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))

        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '0'])
        if menu_choice == '0':
            break
        
        elif menu_choice == '1':
            db_conn.test_connection()

        elif menu_choice == '2':
            show_table_information()

        elif menu_choice == '3':
            show_query_statistics()

        elif menu_choice == '4':
            display_disk_usage()

        elif menu_choice == '5':
            display_thread_information()

        elif menu_choice == '6':
            db_management.truncate_analysis_data_tables()

        input("\nPress any key to continue.")

def show_table_information():
    try:
        table_data = db_management.list_tables()
        app_display.display_tables_info(table_data)
    except Exception as e:
        logging_utils.log_error("Error displaying table information", e)

def show_query_statistics():
    try:
        query_stats = db_info.get_query_statistics()
        app_display.display_query_statistics(query_stats)
    except Exception as e:
        logging_utils.log_error("Error displaying query statistics", e)

def display_disk_usage():
    try:
        disk_usage = db_info.get_disk_usage()
        app_display.display_disk_usage(disk_usage)
    except Exception as e:
        logging_utils.log_error("Error displaying disk usage", e)

def display_thread_information():
    try:
        thread_info = db_info.get_thread_information()
        app_display.display_thread_information(thread_info)
    except Exception as e:
        logging_utils.log_error("Error displaying thread information", e)
