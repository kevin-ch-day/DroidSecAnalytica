# DBUtils.py

import mysql.connector
from mysql.connector import Error
import logging
from contextlib import contextmanager
from typing import Dict, List

from . import database_manager, database_utils

# Context manager for database connection
@contextmanager
def database_connection():
    conn = database_manager.connect_to_database()
    try:
        yield conn
    finally:
        database_manager.close_database_connection(conn)

def test_database_connection():
    conn = None
    try:
        conn = database_manager.connect_to_database()
        if conn == None:
            print("Error connecting to database\n")
            return
        elif conn.is_connected():
            logging.info("Database connection successful.")
        else:
            logging.error("Database connection failed.")
    except mysql.connector.Error as e:
        logging.error(f"Database connection failed: {e}")
    finally:
        if conn and conn.is_connected():
            database_manager.close_database_connection(conn)

def run_sql(sql, values=None, fetch=False):
    with database_connection() as conn:
        return database_manager.execute_sql(conn, sql, values, fetch)

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
        formatted_uptime = database_utils.format_seconds_to_dhms(int(uptime[1]))
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
        where table_schema = 'droidsecanalytica'
        GROUP BY table_schema;
        """
        cursor.execute(sql)
        disk_usage = cursor.fetchall()
        database_utils.format_disk_usage(disk_usage)
    except mysql.connector.Error as e:
        logging.error(f"Error displaying disk usage: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while displaying disk usage: {e}")

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

def update_records_no_virustotal_match(record_id):
    try:
        conn = database_manager.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = "UPDATE android_malware_hashes SET no_virustotal_match = 1 WHERE id = %s"
                cursor.execute(sql, (record_id,))
                conn.commit()
                if cursor.rowcount > 0:
                    print(f"Database record updated.")
                else:
                    print(f"Database record not updated. Exiting...")
    except Exception as e:
        print(f"Error updating record ID {record_id}: {e}")
    finally:
        if conn:
            conn.close()

def get_total_hash_records():
    conn = database_manager.connect_to_database()
    if conn:
        with conn.cursor() as cursor:
            print("Fetching records from the database...")
            cursor.execute("SELECT * FROM android_malware_hashes")
            records = cursor.fetchall()
            total_records = len(records)
            print(f"Total records: {total_records}")
    
    return records

def check_for_hash_record(hash_dict):
    try:
        conn = database_manager.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = "SELECT id, md5, sha1, sha256 FROM malware_hashes "
                sql += f"where md5 = {hash_dict['MD5']} or sha1 = {hash_dict['SHA1']} or sha256 = {hash_dict['SHA256']} "
                sql += "order by id"
                cursor.execute(sql)
                result = cursor.fetchall()
                if result:
                    return True
                else:
                    return False
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def check_if_hash_analyzed(hash_dict):
    hash_record_id = []
    try:
        conn = database_manager.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = "SELECT id, md5, sha1, sha256 FROM malware_hashes "
                sql += f"where md5 = {hash_dict['MD5']} or sha1 = {hash_dict['SHA1']} or sha256 = {hash_dict['SHA256']} "
                sql += "order by id"
                cursor.execute(sql)
                result = cursor.fetchall()
                if result:
                    for x in result:
                        hash_record_id.append(x)
                        if len(hash_record_id) == 0:
                            return False
                        else:
                            return True
                else:
                    return False
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def get_total_records_to_process():
    try:
        conn = database_manager.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = """
                    SELECT COUNT(*) FROM android_malware_hashes
                    WHERE id NOT IN (SELECT id FROM android_malware_hashes WHERE no_virustotal_match = 1)
                    AND (md5 IS NULL OR sha1 IS NULL OR sha256 IS NULL);
                """
                cursor.execute(sql)
                result = cursor.fetchone()
                if result:
                    return result[0]
                else:
                    return 0
    except Exception as e:
        print(f"Error counting records with no match: {e}")
    finally:
        conn.close()

# Create apk sample record
def create_apk_record(filename, filesize, md5, sha1, sha256):
    sql = "INSERT INTO apk_samples (...) VALUES (%s, %s, %s, %s, %s)"
    values = (filename, filesize, md5, sha1, sha256)
    run_sql(sql, values)

def insert_data_into_malware_hashes(file_path, data):
    """ Insert parsed data into the database. """
    sql_insert_data = """
        INSERT INTO malware_hashes 
        (name_1, name_2, md5, sha1, sha256, location, month, year)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    for record in data:
        try:
            run_sql(sql_insert_data, record)
        except Exception as e:
            logging.error(f"Error inserting record from {file_path}: {e}")
            logging.error(f"Problematic record: {record}")

    logging.info(f"Data from {file_path} inserted successfully. Total records: {len(data)}")

def get_intent_filters(is_unusual=True):
    try:
        conn = database_manager.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = "SELECT * FROM android_intent_filters x WHERE x.IsUnusual = %s"
                cursor.execute(sql, (1 if is_unusual else 0,))
                results = cursor.fetchall()
                return results if results else []
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

    return False  # Return False if no unusual intent filter found

def get_intent_filter_record_by_name(intent_name: str) -> Dict:
    """Get an intent filter by its name."""
    cursor = cursor(dictionary=True)
    query = "SELECT * FROM android_intent_filters WHERE IntentName = %s"
    cursor.execute(query, (intent_name,))
    result = cursor.fetchone()
    cursor.close()
    return result