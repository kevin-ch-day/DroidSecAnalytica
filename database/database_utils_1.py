# database_utils_1.py

import mysql.connector
import logging
from contextlib import contextmanager

from . import other_utils, database_manager as dbConnect

def log_error(message: str, error: Exception = None):
    if error:
        logging.error(f"{message}: {error}")
    else:
        logging.error(message)

@contextmanager
def managed_database_connection():
    conn = None
    try:
        conn = dbConnect.connect_to_database()
        yield conn
    except mysql.connector.Error as e:
        log_error("Managed database connection failed", e)
        raise
    finally:
        if conn:
            dbConnect.close_database_connection(conn)

def test_database_connection():
    try:
        with managed_database_connection() as conn:
            if conn.is_connected():
                logging.info("Database connection successful.")
    except mysql.connector.Error as e:
        log_error("Database connection failed", e)

def check_for_table(table_name: str) -> bool:
    try:
        with managed_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES LIKE %s;", (table_name,))
            result = cursor.fetchone()
            return bool(result)
    except Exception as e:
        log_error(f"Error checking for table '{table_name}'", e)
        return False    

def database_health_check():
    try:
        with managed_database_connection() as conn:
            display_database_info(conn)
            check_critical_tables(conn, ['users', 'apk_samples', 'android_permissions'])
            display_performance_metrics(conn)
            display_disk_usage(conn)
    except mysql.connector.Error as e:
        log_error("Failed to perform database health check", e)

def display_database_info():
    try:
        with managed_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION();")
            version = cursor.fetchone()
            logging.info(f"Database Version: {version[0]}")

            cursor.execute("SHOW STATUS LIKE 'Uptime';")
            uptime = cursor.fetchone()
            formatted_uptime = other_utils.format_seconds_to_dhms(int(uptime[1]))
            logging.info(f"Server Uptime: {formatted_uptime}")

            cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
            connections = cursor.fetchone()
            logging.info(f"Active Connections: {connections[1]}")
    except Exception as e:
        log_error("Error displaying database info", e)

def check_critical_tables(table_list):
    try:
        # Retrieve the list of all tables in the database
        result = dbConnect.execute_query("SHOW TABLES;", fetch=True)
        existing_tables = {table[0] for table in result}  # Convert to a set for efficient lookup

        # Check for missing tables
        missing_tables = [table for table in table_list if table not in existing_tables]

        if missing_tables:
            logging.warning(f"Missing critical tables: {', '.join(missing_tables)}")
            return False

        logging.info("All critical tables are present.")
        return True
    except Exception as e:
        log_error("Error checking critical tables", e)
        return False

def display_performance_metrics():
    try:
        with managed_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SHOW STATUS LIKE 'Queries';")
            query_count = cursor.fetchone()
            logging.info(f"Total Queries executed: {query_count[1]}")

            cursor.execute("SHOW STATUS LIKE 'Threads_running';")
            threads_running = cursor.fetchone()
            logging.info(f"Threads Running: {threads_running[1]}")
    except Exception as e:
        log_error("Error displaying performance metrics", e)

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
        log_error("Error displaying disk usage", e)
