# database_utils_2

import mysql.connector
from mysql.connector import Error
import logging
from contextlib import contextmanager

from . import database_manager as dbConnect

# Context manager for database connection
@contextmanager
def database_connection():
    conn = dbConnect.connect_to_database()
    try:
        yield conn
    finally:
        dbConnect.close_database_connection(conn)

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

def update_records_no_virustotal_match(record_id):
    try:
        conn = dbConnect.connect_to_database()
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
    conn = dbConnect.connect_to_database()
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
        conn = dbConnect.connect_to_database()
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
