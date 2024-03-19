# db_menu.py

import mysql.connector
from utils import logging_utils, app_display, user_prompts
from . import db_conn, db_config, db_management

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

def execute_query(query, params=None, fetch=False):
    try:
        return db_conn.execute_query(query, params=params, fetch=fetch)
    except mysql.connector.Error as e:
        logging_utils.log_error("Database query failed", e)
        return []

def disk_usage(min_size_mb: float = 0.0):
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
    return execute_query(query, params=(db_config.DB_DATABASE, min_size_mb), fetch=True)

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
    try:
        table_data = db_management.list_tables()
        app_display.display_tables_info(table_data)
    except Exception as e:
        logging_utils.log_error("Error displaying table information", e)

def show_query_statistics():
    try:
        query_stats = get_query_statistics()
        app_display.display_query_statistics(query_stats)
    except Exception as e:
        logging_utils.log_error("Error displaying query statistics", e)

def display_disk_usage():
    try:
        disk_usage = disk_usage()
        app_display.display_disk_usage(disk_usage)
    except Exception as e:
        logging_utils.log_error("Error displaying disk usage", e)

def display_thread_information():
    try:
        thread_info = thread_summary()
        app_display.display_thread_information(thread_info)
    except Exception as e:
        logging_utils.log_error("Error displaying thread information", e)