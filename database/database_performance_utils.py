import mysql.connector
from contextlib import contextmanager

from . import other_utils, database_manager as dbConnect

@contextmanager
def managed_database_connection():
    conn = None
    try:
        conn = dbConnect.connect_to_database()
        yield conn
    except mysql.connector.Error as e:
        dbConnect.log_error("Managed database connection failed", e)
        raise
    finally:
        if conn:
            dbConnect.close_database_connection(conn)

def database_health_check():
    try:
        display_database_info()
        #check_critical_tables(['users', 'apk_samples', 'android_permissions'])
        #display_performance_metrics()
        #display_disk_usage()
    except mysql.connector.Error as e:
        dbConnect.log_error("Failed to perform database health check", e)

def display_database_info():
    try:
        with managed_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION();")
            version = cursor.fetchone()
            print(f"Database Version: {version[0]}")

            cursor.execute("SHOW STATUS LIKE 'Uptime';")
            uptime = cursor.fetchone()
            formatted_uptime = other_utils.format_seconds_to_dhms(int(uptime[1]))
            print(f"Server Uptime: {formatted_uptime}")

            cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
            connections = cursor.fetchone()
            print(f"Active Connections: {connections[1]}")
    except Exception as e:
        dbConnect.log_error("Error displaying database info", e)

def check_critical_tables(table_list):
    try:
        # Retrieve the list of all tables in the database
        result = dbConnect.execute_query("SHOW TABLES;", fetch=True)
        existing_tables = {table[0] for table in result}  # Convert to a set for efficient lookup

        # Check for missing tables
        missing_tables = [table for table in table_list if table not in existing_tables]

        if missing_tables:
            print(f"Missing critical tables: {', '.join(missing_tables)}")
            return False

        print("All critical tables are present.")
        return True
    except Exception as e:
        dbConnect.log_error("Error checking critical tables", e)
        return False
    
def display_performance_metrics():
    try:
        with managed_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SHOW STATUS LIKE 'Queries';")
            query_count = cursor.fetchone()
            print(f"Total Queries executed: {query_count[1]}")

            cursor.execute("SHOW STATUS LIKE 'Threads_running';")
            threads_running = cursor.fetchone()
            print(f"Threads Running: {threads_running[1]}")
    except Exception as e:
        dbConnect.log_error("Error displaying performance metrics", e)

def display_disk_usage():
    try:
        with managed_database_connection() as conn:
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
            other_utils.format_disk_usage(disk_usage)
    except Exception as e:
        dbConnect.log_error("Error displaying disk usage", e)

def database_health_check():
    try:
        display_database_info()
        check_critical_tables(['droidsec_users', 'apk_samples', 'android_permissions'])
        display_performance_metrics()
        display_disk_usage()
    except mysql.connector.Error as e:
        dbConnect.log_error("Failed to perform database health check", e)

def display_performance_metrics(conn):
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
    sql = "SHOW STATUS WHERE `variable_name` = 'Uptime' OR `variable_name` LIKE '%bytes%' OR `variable_name` LIKE '%table%' OR `variable_name` LIKE 'Key_%';"
    cursor.execute(sql)
    for variable_name, value in cursor.fetchall():
        print(f"{variable_name.replace('_', ' ').title()}: {value}")
