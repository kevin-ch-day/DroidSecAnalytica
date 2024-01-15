# DBPerformance.py

import logging
import mysql.connector
import time
from contextlib import contextmanager
from utils import app_utils, app_display

import database.DBConnectionManager as dbConnect

# Context manager for database connection
@contextmanager
def database_connection():
    conn = dbConnect.connect_to_database()
    try:
        yield conn
    finally:
        dbConnect.close_database_connection(conn)

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
        conn = dbConnect.connect_to_database()
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

def show_query_count(cursor):
    cursor.execute("SHOW STATUS LIKE 'Queries';")
    query_count = cursor.fetchone()
    print(f"\nTotal Queries Executed: {query_count[1]}")

def show_slow_queries(cursor):
    cursor.execute("SHOW STATUS LIKE 'Slow_queries';")
    slow_queries = cursor.fetchone()
    print(f"Slow Queries: {slow_queries[1]}")

def show_memory_usage(cursor):
    cursor.execute("SHOW STATUS LIKE 'Max_used_connections';")
    max_used_connections = cursor.fetchone()
    print(f"Max Used Connections: {max_used_connections[1]}")

def show_thread_info(cursor):
    cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
    threads_connected = cursor.fetchone()
    print(f"Threads Connected: {threads_connected[1]}")

    cursor.execute("SHOW STATUS LIKE 'Threads_running';")
    threads_running = cursor.fetchone()
    print(f"Threads Running: {threads_running[1]}")

def show_detailed_server_status(cursor):
    cursor.execute("SHOW STATUS WHERE `variable_name` = 'Uptime' OR `variable_name` LIKE '%bytes%' OR `variable_name` LIKE '%table%' OR `variable_name` LIKE 'Key_%';")
    for variable_name, value in cursor.fetchall():
        print(f"{variable_name.replace('_', ' ').title()}: {value}")