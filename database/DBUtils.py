# DBUtils.py

import mysql.connector
import logging
from contextlib import contextmanager
import database.DBConnectionManager as dbConnect

# Context manager for database connection
@contextmanager
def database_connection():
    conn = dbConnect.connect_to_database()
    try:
        yield conn
    finally:
        dbConnect.close_database_connection(conn)

def test_database_connection():
    try:
        with database_connection() as conn:
            if conn.is_connected():
                logging.info("Database connection successful.")
            else:
                logging.error("Database connection failed.")
    except mysql.connector.Error as e:
        logging.error(f"Database connection failed: {e}")

def run_sql(sql, values=None, fetch=False):
    with database_connection() as conn:
        return dbConnect.execute_sql(conn, sql, values, fetch)

def check_for_table(table_name):
    try:
        with database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES LIKE %s;", (table_name,))
            result = cursor.fetchone()
            return bool(result)
    except mysql.connector.Error as e:
        if e.errno == mysql.connector.errorcode.ER_NO_SUCH_TABLE:
            logging.info(f"Table '{table_name}' does not exist.")
        else:
            logging.error(f"Error checking for table '{table_name}': {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

def create_apk_record(filename, filesize, md5, sha1, sha256):
    sql = "INSERT INTO apk_samples (...) VALUES (%s, %s, %s, %s, %s)"
    values = (filename, filesize, md5, sha1, sha256)
    return run_sql(sql, values)

def database_health_check():
    with database_connection() as conn:
        if conn:
            display_database_info(conn)
            check_critical_tables(conn, ['users', 'apk_samples', 'android_permissions'])
            display_performance_metrics(conn)
            display_disk_usage(conn)
        else:
            logging.error("Failed to establish a database connection.")

def display_database_info(conn):
    try:
        cursor = conn.cursor()
        # Display the database version
        cursor.execute("SELECT VERSION();")
        version = cursor.fetchone()
        print(f"Database Version: {version[0]}")

        # Display the server uptime
        cursor.execute("SHOW STATUS LIKE 'Uptime';")
        uptime = cursor.fetchone()
        formatted_uptime = format_seconds_to_dhms(int(uptime[1]))
        print(f"Server Uptime: {formatted_uptime}")

        # Display the number of active connections
        cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
        connections = cursor.fetchone()
        print(f"Active Connections: {connections[1]}")

        # Any other relevant database info can be added here
    except mysql.connector.Error as e:
        logging.error(f"Error displaying database info: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while displaying database info: {e}")

def check_critical_tables(conn, table_list):
    try:
        cursor = conn.cursor()
        missing_tables = []
        for table_name in table_list:
            cursor.execute("SHOW TABLES LIKE %s;", (table_name,))
            result = cursor.fetchone()
            if not result:
                missing_tables.append(table_name)

        if missing_tables:
            logging.warning(f"Missing critical tables: {', '.join(missing_tables)}")
            return False
        else:
            logging.info("All critical tables are present.")
            return True
    except mysql.connector.Error as e:
        logging.error(f"Error checking critical tables: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking critical tables: {e}")
        return False

def display_performance_metrics(conn):
    try:
        cursor = conn.cursor()
        # Display total number of queries executed
        cursor.execute("SHOW STATUS LIKE 'Queries';")
        query_count = cursor.fetchone()
        print(f"Total Queries executed: {query_count[1]}")

        # Add additional performance metrics as needed
        # Example: Threads running
        cursor.execute("SHOW STATUS LIKE 'Threads_running';")
        threads_running = cursor.fetchone()
        print(f"Threads Running: {threads_running[1]}")

        # Additional metrics can be added here
    except mysql.connector.Error as e:
        logging.error(f"Error displaying performance metrics: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while displaying performance metrics: {e}")


def display_disk_usage(conn):
    try:
        cursor = conn.cursor()
        sql = """
        SELECT table_schema 'Database',
               ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 'Size in MB'
        FROM information_schema.TABLES
        GROUP BY table_schema;
        """
        cursor.execute(sql)
        disk_usage = cursor.fetchall()
        format_disk_usage(disk_usage)
    except mysql.connector.Error as e:
        logging.error(f"Error displaying disk usage: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while displaying disk usage: {e}")

def format_disk_usage(disk_usage):
    if not disk_usage:
        print("No disk usage data available.")
        return

    print(f"\n{'Database'.ljust(20)} | {'Size in MB'.rjust(10)}")
    print("-" * 33)
    for db_name, size_mb in disk_usage:
        print(f"{db_name.ljust(20)} | {str(size_mb).rjust(10)}")

def format_seconds_to_dhms(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def display_tables_info():
    tables_info = list_tables()
    if not tables_info:
        logging.error("No table information available or failed to retrieve table information.")
        return

    # Formatting and displaying the table information
    print("\nDatabase Tables Information:")
    print(f"{'Table Name'.ljust(30)} | {'# of Columns'.rjust(15)} | {'# of Rows'.rjust(15)}")
    print("-" * 65)
    
    for table_name, num_columns, num_rows in tables_info:
        print(f"{table_name.ljust(30)} | {str(num_columns).rjust(15)} | {str(num_rows).rjust(15)}")

def list_tables():
    table_info = []
    with database_connection() as conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES;")
            tables = cursor.fetchall()
            for (table_name,) in tables:
                cursor.execute(f"SHOW COLUMNS FROM {table_name};")
                num_columns = len(cursor.fetchall())
                cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
                num_rows = cursor.fetchone()[0]
                table_info.append((table_name, num_columns, num_rows))
        except mysql.connector.Error as e:
            logging.error(f"Error listing tables: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while listing tables: {e}")
    return table_info

def empty_table(table_name):
    with database_connection() as conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
            cursor.execute(f"TRUNCATE TABLE {table_name};")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
            logging.info(f"Table '{table_name}' has been successfully emptied.")
            return True
        except mysql.connector.Error as e:
            logging.error(f"Error emptying table '{table_name}': {e}")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred while emptying table '{table_name}': {e}")
            return False

def viewAndroidHashTableSummary():
    sql = "SELECT COUNT(*) FROM android_malware_hashes"
    result = run_sql(sql, None, True)
    if result:
        logging.info(f"Total Records in Database: {result[0][0]}")
    else:
        logging.error("Failed to retrieve hash table summary.")

def create_android_malware_hash_table():
    with database_connection() as conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `android_malware_hashes` (
                    `id` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    `malware_name_1` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
                    `malware_name_2` varchar(250) DEFAULT NULL,
                    `md5` varchar(250) DEFAULT NULL,
                    `sha1` varchar(250) DEFAULT NULL,
                    `sha256` varchar(250) DEFAULT NULL,
                    `location` varchar(100) DEFAULT NULL,
                    `month` varchar(100) DEFAULT NULL,
                    `year` varchar(10) DEFAULT NULL
                );
            """)
            logging.info("Table 'android_malware_hashes' created successfully.")
            return True
        except mysql.connector.Error as e:
            logging.error(f"Error creating table 'android_malware_hashes': {e}")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred while creating table 'android_malware_hashes': {e}")
            return False
