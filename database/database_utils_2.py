import mysql.connector
import logging

from . import other_utils, database_manager as dbConnect

def log_error(message: str, error: Exception = None):
    if error:
        logging.error(f"{message}: {error}")
    else:
        logging.error(message)

def execute_query(query: str, params: tuple = None, fetch: bool = False):
    with dbConnect.managed_database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall() if fetch else None

def display_tables_info():
    tables_info = list_tables()
    if not tables_info:
        log_error("No table information available or failed to retrieve table information.")
        return

    print("\nDatabase Tables Information:")
    print(f"{'Table Name'.ljust(30)} | {'# of Columns'.rjust(15)} | {'# of Rows'.rjust(15)}")
    print("-" * 65)
    
    for table_name, num_columns, num_rows in tables_info:
        print(f"{table_name.ljust(30)} | {str(num_columns).rjust(15)} | {str(num_rows).rjust(15)}")

def list_tables():
    try:
        result = execute_query("SHOW TABLES;", fetch=True)
        table_info = []
        for (table_name,) in result:
            num_columns = len(execute_query(f"SHOW COLUMNS FROM {table_name};", fetch=True))
            num_rows = execute_query(f"SELECT COUNT(*) FROM {table_name};", fetch=True)[0][0]
            table_info.append((table_name, num_columns, num_rows))
        return table_info
    except Exception as e:
        log_error("Error listing tables", e)
        return []

# ... (continued from the previous part of the script)

# Function to view Android hash table summary
def viewAndroidHashTableSummary():
    try:
        result = execute_query("SELECT COUNT(*) FROM android_malware_hashes", fetch=True)
        if result:
            logging.info(f"Total Records in Database: {result[0][0]}")
        else:
            log_error("Failed to retrieve hash table summary.")
    except Exception as e:
        log_error("Error retrieving hash table summary", e)

# Function to create android malware hash table
def create_android_malware_hash_table():
    try:
        sql_create_table = """
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
        """
        execute_query(sql_create_table, fetch=False)
        logging.info("Table 'android_malware_hashes' created successfully.")
        return True
    except Exception as e:
        log_error("Error creating table 'android_malware_hashes'", e)
        return False

# Function to update records with no VirusTotal match
def update_records_no_virustotal_match(record_id):
    try:
        sql_update = "UPDATE android_malware_hashes SET no_virustotal_match = 1 WHERE id = %s"
        execute_query(sql_update, (record_id,), fetch=False)
        logging.info("Database record updated.")
    except Exception as e:
        log_error(f"Error updating record ID {record_id}", e)

# Function to get total hash records
def get_total_hash_records():
    try:
        records = execute_query("SELECT * FROM android_malware_hashes", fetch=True)
        total_records = len(records)
        logging.info(f"Total records: {total_records}")
        return records
    except Exception as e:
        log_error("Error fetching total hash records", e)
        return []

def check_for_hash_record(hash_dict):
    try:
        sql = """
            SELECT id, md5, sha1, sha256 
            FROM malware_hashes 
            WHERE md5 = %s OR sha1 = %s OR sha256 = %s 
            ORDER BY id
        """
        params = (hash_dict['MD5'], hash_dict['SHA1'], hash_dict['SHA256'])
        result = execute_query(sql, params, fetch=True)
        return bool(result)
    except Exception as e:
        log_error("Error checking for hash record", e)
        return False

def empty_table(table_name):
    try:
        execute_query("SET FOREIGN_KEY_CHECKS = 0;", fetch=False)
        execute_query(f"TRUNCATE TABLE {table_name};", fetch=False)
        execute_query("SET FOREIGN_KEY_CHECKS = 1;", fetch=False)
        logging.info(f"Table '{table_name}' has been successfully emptied.")
        return True
    except Exception as e:
        log_error(f"Error emptying table '{table_name}'", e)
        return False

def check_for_hash_record(hash_dict):
    try:
        sql = """
            SELECT id, md5, sha1, sha256 
            FROM malware_hashes 
            WHERE md5 = %s OR sha1 = %s OR sha256 = %s 
            ORDER BY id
        """
        params = (hash_dict['MD5'], hash_dict['SHA1'], hash_dict['SHA256'])
        result = execute_query(sql, params, fetch=True)
        return bool(result)
    except Exception as e:
        log_error("Error checking for hash record", e)
        return False

# Function to empty a specific table
def empty_table(table_name):
    try:
        execute_query("SET FOREIGN_KEY_CHECKS = 0;", fetch=False)
        execute_query(f"TRUNCATE TABLE {table_name};", fetch=False)
        execute_query("SET FOREIGN_KEY_CHECKS = 1;", fetch=False)
        logging.info(f"Table '{table_name}' has been successfully emptied.")
        return True
    except Exception as e:
        log_error(f"Error emptying table '{table_name}'", e)
        return False