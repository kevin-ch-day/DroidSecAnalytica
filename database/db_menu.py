# db_menu.py

import mysql.connector
from utils import logging_utils, app_display, user_prompts
from . import db_conn, db_management, orphaned_analysis_cleanup, db_util_func

logger = logging_utils.get_logger(__name__)

# Database menu
def database_menu():
    """
    Displays the interactive Database Menu, allowing users to execute various database-related operations.
    """
    while True:
        print(app_display.format_menu_title("Database Management Menu"))

        print(app_display.format_menu_option(1, "Test Database Connection"))
        print(app_display.format_menu_option(2, "Display Table Information"))
        print(app_display.format_menu_option(3, "Show Query Statistics"))
        print(app_display.format_menu_option(4, "Display Disk Usage"))
        print(app_display.format_menu_option(5, "Show Thread Information"))
        print(app_display.format_menu_option(6, "Cleanup Orphaned Analysis Data"))
        print(app_display.format_menu_option(7, "Clear Analysis Tables"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))

        menu_choice = user_prompts.user_menu_choice("\nEnter your choice (0-7): ", 
                                                    ['0', '1', '2', '3', '4', '5', '6', '7'])

        if menu_choice == '0':
            print("\nReturning to Main Menu...")
            break

        elif menu_choice == '1':
            print("\n[INFO] Testing database connection...\n")
            db_conn.test_connection()

        elif menu_choice == '2':
            print("\n[INFO] Retrieving database table information...\n")
            show_table_information()

        elif menu_choice == '3':
            print("\n[INFO] Fetching database query execution statistics...\n")
            display_query_statistics()

        elif menu_choice == '4':
            print("\n[INFO] Analyzing database disk usage...\n")
            db_util_func.disk_usage_report()

        elif menu_choice == '5':
            print("\n[INFO] Displaying database thread activity...\n")
            display_thread_information()

        elif menu_choice == '6':
            print("\n[INFO] Running orphaned analysis cleanup...\n")
            orphaned_analysis_cleanup.run_orphaned_analysis_cleanup()

        elif menu_choice == '7':
            print("\n[WARNING] This will clear all analysis data. Proceed with caution.\n")
            confirm = user_prompts.user_menu_choice("Are you sure you want to clear analysis tables? (yes/no): ", ['yes', 'no'])
            if confirm == 'yes':
                db_management.truncate_analysis_data_tables()
            else:
                print("\nOperation canceled. Returning to the menu.\n")

        input("\nPress Enter to continue...")

def execute_query(query, params=None, fetch=False):
    try:
        return db_conn.execute_query(query, params=params, fetch=fetch)
    except mysql.connector.Error:
        logger.exception("Database query failed")
        return []

def database_summary():
    try:
        with db_conn.database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION();")
            version = cursor.fetchone()
            cursor.execute("SHOW STATUS LIKE 'Uptime';")
            uptime = cursor.fetchone()
            cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
            connections = cursor.fetchone()
            return version, uptime, connections
    except mysql.connector.Error:
        logger.exception("Error fetching database information")
        return None

def thread_summary():
    query = """
    SELECT VARIABLE_NAME AS 'Metric', VARIABLE_VALUE AS 'Value'
    FROM information_schema.GLOBAL_STATUS
    WHERE VARIABLE_NAME IN ('Threads_connected', 'Threads_running', 'Threads_cached', 'Threads_created', 'Threads_waiting');
    """
    return execute_query(query, fetch=True)

def get_query_statistics():
    query = "SHOW STATUS LIKE 'Queries';"
    return execute_query(query, fetch=True)

def show_table_information():
    database_tables_info = db_management.list_tables()
    if not database_tables_info:
        print("No table information available.")
        return

    table_header = "Table Name"
    columns_header = "Columns"
    rows_header = "Rows"

    try:
        max_table_len = max(len(table_header), max(len(table[0]) for table in database_tables_info)) + 2
        max_columns_len = max(len(columns_header), max(len(str(table[1])) for table in database_tables_info)) + 2
        max_rows_len = max(len(rows_header), max(len(str(table[2])) for table in database_tables_info)) + 2

        print(f"{table_header.ljust(max_table_len)} | {columns_header.ljust(max_columns_len)} | {rows_header.ljust(max_rows_len)}")
        print("-" * (max_table_len + max_columns_len + max_rows_len + 6))

        for table in database_tables_info:
            if len(table) < 3:
                print(f"Debug: Incomplete table information for: {table}")
                continue

            table_name, num_columns, num_rows = table
            print(f"{table_name.ljust(max_table_len)} | {str(num_columns).ljust(max_columns_len)} | {str(num_rows).ljust(max_rows_len)}")

    except Exception as e:
        print(f"Error displaying table information: {str(e)}")

# Display query statistics
def display_query_statistics():
    try:
        query_stats = get_query_statistics()
        if query_stats:
            print("\nQuery Statistics:")
            for stat in query_stats:
                print(f"{stat[0]}: {stat[1]}")
        else:
            print("No query statistics available.")
    except Exception:
        logger.exception("Error displaying query statistics")

# Display threat information
def display_thread_information():
    try:
        thread_info = thread_summary()
        if thread_info:
            print("\nThread Information:")
            
            # Formatting for a neat tabular display
            max_metric_length = max(len(info[0]) for info in thread_info)
            for metric, value in thread_info:
                print(f"{metric:<{max_metric_length}} : {value}")

        else:
            print("No thread information available.")

    except Exception:
        logger.exception("Error displaying thread information")
