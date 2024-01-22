# database_performance.py

import logging
import mysql.connector
from utils import app_utils, app_display
import database.database_manager as database_conn

def performance_menu():
    print(app_display.format_menu_title("Database Performance Metrics"))
    print(app_display.format_menu_option(1, "Query Count"))
    print(app_display.format_menu_option(2, "Slow Queries"))
    print(app_display.format_menu_option(3, "Memory Usage"))
    print(app_display.format_menu_option(4, "Thread Information"))
    print(app_display.format_menu_option(5, "Detailed Server Status"))
    print(app_display.format_menu_option(0, "Exit"))
    
def dispay_performance():
    try:
        with database_conn.database_connection() as conn:
            cursor = conn.cursor()

            while True:
                performance_menu()
                choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6','0'])

                if choice == '1':
                    show_query_count(cursor)
                elif choice == '2':
                    show_slow_queries(cursor)
                elif choice == '3':
                    show_memory_usage(cursor)
                elif choice == '4':
                    show_thread_info(cursor)
                elif choice == '5':
                    show_detailed_server_status(cursor)
                elif choice == '0':
                    print("Exiting performance metrics...")
                    break
                else:
                    print("Invalid option. Please try again.")

    except mysql.connector.Error as e:
        logging.error(f"Error in performance metrics: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in performance metrics: {e}")