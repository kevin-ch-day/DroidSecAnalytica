# database_menu.py

import mysql.connector
from contextlib import contextmanager
from utils import app_display, user_prompts, app_utils
from . import database_manager as dbConnect

# Define a context manager for database connections
@contextmanager
def managed_database_connection():
    try:
        conn = dbConnect.connect_to_database()
        yield conn
    except mysql.connector.Error as e:
        dbConnect.log_error("Managed database connection failed", e)
        raise
    finally:
        if conn:
            dbConnect.close_database_connection(conn)

# Function to display the database management menu
def display_database_menu():
    print(app_display.format_menu_title("Database Management Menu"))
    print(app_display.format_menu_option(1, "Test Database Connection"))
    print(app_display.format_menu_option(2, "List Database Tables"))
    print(app_display.format_menu_option(3, "Combined Database Health Check"))
    print(app_display.format_menu_option(4, "Clear Android Malware Hash Table"))
    print(app_display.format_menu_option(5, "Query Statistics"))
    print(app_display.format_menu_option(6, "Performance Metrics"))
    print(app_display.format_menu_option(7, "Disk Usage"))
    print(app_display.format_menu_option(8, "Thread Information"))
    print(app_display.format_menu_option(0, "Return to main menu"))

# Function to execute the database management menu
def database_management_menu():
    while True:
        display_database_menu()
        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '0'])

        if menu_choice == '0':
            return
        
        elif menu_choice == '1':
            dbConnect.test_database_connection()

        elif menu_choice == '2':
            conn = dbConnect.connect_to_database()
            dbConnect.display_tables_info(conn)

        elif menu_choice == '3':
            conn = dbConnect.connect_to_database()
            database_health_check(conn)

        elif menu_choice == '4':
            conn = dbConnect.connect_to_database()
            dbConnect.empty_table(conn, 'android_malware_hashes')

        elif menu_choice == '5':
            conn = dbConnect.connect_to_database()
            show_query_count(conn)

        elif menu_choice == '6':
            conn = dbConnect.connect_to_database()
            show_performance_metrics(conn)

        elif menu_choice == '7':
            conn = dbConnect.connect_to_database()
            show_disk_usage(conn)

        elif menu_choice == '8':
            conn = dbConnect.connect_to_database()
            show_thread_info(conn)

        input("\nPress any key to continue.")

# Function to show query count
def show_query_count(conn):
    cursor = conn.cursor()
    cursor.execute("SHOW STATUS LIKE 'Queries';")
    query_count = cursor.fetchone()
    print(f"\nTotal Queries Executed: {query_count[1]}")

# Function to show performance metrics
def show_performance_metrics(conn):
    try:
        cursor = conn.cursor()
        metrics = ["Queries", "Threads_running"]
        for metric in metrics:
            cursor.execute(f"SHOW STATUS LIKE '{metric}';")
            result = cursor.fetchone()
            if result:
                print(f"{metric}: {result[1]}")
            else:
                print(f"Metric '{metric}' not found.")
    except mysql.connector.Error as e:
        print(f"Error displaying performance metrics: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while displaying performance metrics: {e}")

# Function to show disk usage
def show_disk_usage(conn):
    try:
        cursor = conn.cursor()
        sql = """
        SELECT table_schema 'Database',
               ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 'Size in MB'
        FROM information_schema.TABLES
        WHERE table_schema = 'droidsecanalytica'
        GROUP BY table_schema;
        """
        cursor.execute(sql)
        disk_usage = cursor.fetchall()
        app_utils.format_disk_usage(disk_usage)
    except Exception as e:
        dbConnect.log_error("Error displaying disk usage", e)

# Function to show thread information
def show_thread_info(conn):
    try:
        cursor = conn.cursor()
        cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
        threads_connected = cursor.fetchone()
        print(f"Threads Connected: {threads_connected[1]}")

        cursor.execute("SHOW STATUS LIKE 'Threads_running';")
        threads_running = cursor.fetchone()
        print(f"Threads Running: {threads_running[1]}")
    except Exception as e:
        dbConnect.log_error("Error displaying thread information", e)

# Function to perform a combined database health check
def database_health_check(conn):
    try:
        print("Performing combined database health check...")
        display_database_info(conn)
        show_performance_metrics(conn)
        show_disk_usage(conn)
    except mysql.connector.Error as e:
        dbConnect.log_error("Failed to perform combined database health check", e)

# Function to display database information
def display_database_info(conn):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION();")
        version = cursor.fetchone()
        print(f"Database Version: {version[0]}")

        cursor.execute("SHOW STATUS LIKE 'Uptime';")
        uptime = cursor.fetchone()
        formatted_uptime = app_utils.format_seconds_to_dhms(int(uptime[1]))
        print(f"Server Uptime: {formatted_uptime}")

        cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
        connections = cursor.fetchone()
        print(f"Active Connections: {connections[1]}")
    except Exception as e:
        dbConnect.log_error("Error displaying database info", e)
