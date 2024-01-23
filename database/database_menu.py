# database_menu.py

import mysql.connector
from utils import app_display, user_prompts, app_utils
from . import database_manager as dbConnect

# Execute the database management menu
def database_management_menu():
    while True:
        print(app_display.format_menu_title("Database Management Menu"))
        print(app_display.format_menu_option(1, "Test Database Connection"))
        print(app_display.format_menu_option(2, "Display Table Information"))
        print(app_display.format_menu_option(3, "Perform Health Check"))
        print(app_display.format_menu_option(4, "Show Query Statistics"))
        print(app_display.format_menu_option(5, "Display Disk Usage"))
        print(app_display.format_menu_option(6, "Show Thread Information"))
        print(app_display.format_menu_option(7, "Clear Android Malware Hash Table"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))
        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '7', '0'])

        if menu_choice == '0':
            return
        
        elif menu_choice == '1':
            dbConnect.test_database_connection()

        elif menu_choice == '2':
            table_data = dbConnect.get_database_tables_info()
            app_display.display_tables_info(table_data)

        elif menu_choice == '3':
            perform_health_check()

        elif menu_choice == '4':
            query_stats = dbConnect.get_query_statistics()
            app_display.display_query_statistics(query_stats)

        elif menu_choice == '5':
            disk_usage = dbConnect.get_disk_usage()
            app_display.display_disk_usage(disk_usage)

        elif menu_choice == '6':
            thread_info = dbConnect.get_thread_information()
            app_display.display_thread_information(thread_info)

        elif menu_choice == '7':
            dbConnect.empty_table('android_malware_hashes')

        input("\nPress any key to continue.")

def perform_health_check():
    try:
        print("Performing combined database health check...")
        with dbConnect.managed_database_connection() as conn:
            if conn is not None:
                dbConnect.log_info("Database connection established.")
                display_database_info(conn)
                display_disk_usage(conn)
            else:
                print("Database connection could not be established.")
                dbConnect.log_warning("Database connection could not be established.")
    except mysql.connector.Error as e:
        dbConnect.log_error("Database operation failed during health check", e)
    except Exception as e:
        dbConnect.log_error("Unexpected error during health check", e)
    finally:
        print("Health check completed.")

def display_disk_usage(conn):
    try:
        disk_usage = dbConnect.get_disk_usage(conn)
        if disk_usage:
            app_utils.format_disk_usage(disk_usage)
        else:
            print("No disk usage data available.")
            dbConnect.log_warning("No disk usage data available.")
    except Exception as e:
        dbConnect.log_error("Error displaying disk usage", e)

def display_database_info(conn):
    try:
        db_info = dbConnect.get_database_info(conn)
        if db_info:
            app_utils.format_database_info(db_info)
        else:
            print("Database information is not available.")
            dbConnect.log_warning("Database information is not available.")
    except Exception as e:
        dbConnect.log_error("Error displaying database info", e)

def show_thread_information(conn):
    try:
        thread_info = dbConnect.get_thread_information(conn)
        if thread_info:
            app_utils.format_thread_info(thread_info)
        else:
            print("Thread information is not available.")
            dbConnect.log_warning("Thread information is not available.")
    except Exception as e:
        dbConnect.log_error("Error displaying thread information", e)

def show_query_statistics(conn):
    try:
        query_stats = dbConnect.get_query_statistics(conn)
        if query_stats:
            app_utils.format_query_statistics(query_stats)
        else:
            print("Query statistics are not available.")
            dbConnect.log_warning("Query statistics are not available.")
    except Exception as e:
        dbConnect.log_error("Error displaying query statistics", e)
