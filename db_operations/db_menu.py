# db_menu.py

import mysql.connector
from utils import logging_utils, app_display, user_prompts
from . import db_conn, db_config, db_management, db_api_management

# Database menu
def database_menu():
    while True:
        print(app_display.format_menu_title("Database Menu"))
        print(app_display.format_menu_option(1, "Test Database Connection"))
        print(app_display.format_menu_option(2, "Check VirusTotal API Key"))
        print(app_display.format_menu_option(3, "Display Table Information"))
        print(app_display.format_menu_option(4, "Show Query Statistics"))
        print(app_display.format_menu_option(5, "Display Disk Usage"))
        print(app_display.format_menu_option(6, "Clear analysis tables"))
        print(app_display.format_menu_option(7, "Show Thread Information"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))

        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '7','0'])
        if menu_choice == '0':
            break
        
        elif menu_choice == '1':
            db_conn.test_connection()

        elif menu_choice == '2':
            db_api_management.vt_api_key_menu()

        elif menu_choice == '3':
            show_table_information()

        elif menu_choice == '4':
            display_query_statistics()

        elif menu_choice == '5':
            disk_usage_report()

        elif menu_choice == '6':
            db_management.truncate_analysis_data_tables()

        elif menu_choice == '7':
            display_thread_information()

        input("\nPress any key to continue.")

def execute_query(query, params=None, fetch=False):
    try:
        return db_conn.execute_query(query, params=params, fetch=fetch)
    except mysql.connector.Error as e:
        logging_utils.log_error("Database query failed", e)
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
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching database information", e)
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

def tables_summary():
    result = execute_query("SHOW TABLES;", fetch=True)
    table_info = []
    for (table_name,) in result:
        num_columns = len(execute_query(f"SHOW COLUMNS FROM {table_name};", fetch=True))
        num_rows = execute_query(f"SELECT COUNT(*) FROM {table_name};", fetch=True)[0][0]

        size_query = """
        SELECT table_schema 'Database', ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 'Size in MB'
        FROM information_schema.TABLES
        WHERE table_schema = %s AND table_name = %s
        GROUP BY table_schema, table_name;
        """
        size_result = execute_query(size_query, params=(db_config.DB_DATABASE, table_name), fetch=True)
        size_mb = size_result[0][1] if size_result else 0.0

        table_info.append((table_name, num_columns, num_rows, size_mb))
    return table_info

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
    except Exception as e:
        logging_utils.log_error("Error displaying query statistics", e)

def disk_usage_report(min_size_mb: float = 0.0):
    """
    Retrieves and displays disk usage information for all tables in the database.
    Filters tables by minimum size if specified. Provides a summary of total storage.
    """
    query = """
    SELECT table_name AS 'Table',
        ROUND(SUM(data_length) / 1024 / 1024, 2) AS 'Data Size in MB',
        ROUND(SUM(index_length) / 1024 / 1024, 2) AS 'Index Size in MB',
        ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Total Size in MB'
    FROM information_schema.TABLES
    WHERE table_schema = %s
    GROUP BY table_name
    HAVING `Total Size in MB` >= %s
    ORDER BY `Total Size in MB` DESC;
    """
    
    try:
        # Fetch disk usage data
        disk_usage = execute_query(query, params=(db_config.DB_DATABASE, min_size_mb), fetch=True)

        if not disk_usage:
            print("\n[INFO] No disk usage data available.")
            return
        
        # Compute total database usage
        total_data_size = sum(row[1] for row in disk_usage)
        total_index_size = sum(row[2] for row in disk_usage)
        total_db_size = sum(row[3] for row in disk_usage)

        # Identify the largest table (if available)
        largest_table = max(disk_usage, key=lambda x: x[3]) if disk_usage else None

        # Display summary
        print("\n" + "=" * 60)
        print(f" DATABASE DISK USAGE SUMMARY ({db_config.DB_DATABASE})")
        print("=" * 60)
        print(f" Total Tables: {len(disk_usage)}")
        print(f" Largest Table: {largest_table[0]} ({largest_table[3]} MB)" if largest_table else " Largest Table: None")
        print(f" Total Data Size: {total_data_size:.2f} MB")
        print(f" Total Index Size: {total_index_size:.2f} MB")
        print(f" Total Database Size: {total_db_size:.2f} MB")
        print("=" * 60)

        # Determine the longest table name for dynamic column sizing
        max_table_name_length = max(len(row[0]) for row in disk_usage)
        col_widths = [max(35, max_table_name_length), 15, 15, 15]

        # Display Table Headers with Dynamic Column Width
        header = f"{'Table':<{col_widths[0]}} | {'Data Size (MB)':>{col_widths[1]}} | {'Index Size (MB)':>{col_widths[2]}} | {'Total Size (MB)':>{col_widths[3]}}"
        print("\nDisk Usage Details:")
        print("-" * len(header))
        print(header)
        print("-" * len(header))

        # Display Data Rows
        for table, data_size, index_size, total_size in disk_usage:
            print(f"{table:<{col_widths[0]}} | {data_size:>{col_widths[1]}.2f} | {index_size:>{col_widths[2]}.2f} | {total_size:>{col_widths[3]}.2f}")

        # Footer
        print("-" * len(header))

    except Exception as e:
        logging_utils.log_error("Error retrieving and displaying disk usage", e)


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

    except Exception as e:
        logging_utils.log_error("Error displaying thread information", e)