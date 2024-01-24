from utils import logging_utils
from . import db_manager as dbConnect

def check_for_table(table_name: str) -> bool:
    try:
        with dbConnect.database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES LIKE %s;", (table_name,))
            result = cursor.fetchone()
            return bool(result)
    except Exception as e:
        logging_utils.log_error(f"Error checking for table '{table_name}'", e)
        return False
    
def display_tables_info():
    tables_info = list_tables()
    if not tables_info:
        print("No table information available or failed to retrieve table information.")
        return

    print("\nDatabase Tables Information:")
    print(f"{'Table Name':<30} | {'# of Columns':>15} | {'# of Rows':>15}")
    print("-" * 65)
    for table_name, num_columns, num_rows in tables_info:
        print(f"{table_name:<30} | {str(num_columns):>15} | {str(num_rows):>15}")

def list_tables():
    try:
        result = dbConnect.execute_query("SHOW TABLES;", fetch=True)
        table_info = []
        for (table_name,) in result:
            num_columns = len(dbConnect.execute_query(f"SHOW COLUMNS FROM {table_name};", fetch=True))
            num_rows = dbConnect.execute_query(f"SELECT COUNT(*) FROM {table_name};", fetch=True)[0][0]
            table_info.append((table_name, num_columns, num_rows))
        return table_info
    except Exception as e:
        dbConnect.log_error("Error listing tables", e)
        return []
    
def create_android_malware_hash_table():
    try:
        sql_create_table = """
            CREATE TABLE IF NOT EXISTS android_malware_hashes (
                id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                malware_name_1 VARCHAR(255) DEFAULT NULL,
                malware_name_2 VARCHAR(250) DEFAULT NULL,
                md5 VARCHAR(250) DEFAULT NULL,
                sha1 VARCHAR(250) DEFAULT NULL,
                sha256 VARCHAR(250) DEFAULT NULL,
                location VARCHAR(100) DEFAULT NULL,
                month VARCHAR(100) DEFAULT NULL,
                year VARCHAR(10) DEFAULT NULL
            );
        """
        dbConnect.execute_query(sql_create_table, fetch=False)
        print("Table 'android_malware_hashes' created successfully.")
        return True
    except Exception as e:
        dbConnect.log_error("Error creating table 'android_malware_hashes'", e)
        return False
    
def no_virustotal_record_match(record_id):
    try:
        sql_update = "UPDATE android_malware_hashes SET no_virustotal_match = 1 WHERE id = %s"
        dbConnect.execute_query(sql_update, (record_id,), fetch=False)
        print("Database record updated.")
    except Exception as e:
        dbConnect.log_error(f"Error updating record ID {record_id}", e)

def create_apk_record(filename: str, filesize: int, md5: str, sha1: str, sha256: str):
    try:
        sql = "INSERT INTO apk_samples (filename, filesize, md5, sha1, sha256) VALUES (%s, %s, %s, %s, %s)"
        values = (filename, filesize, md5, sha1, sha256)
        dbConnect.execute_query(sql, values)
        logging_utils.log_info("APK record created successfully.")
    except Exception as e:
        logging_utils.log_error("Error creating APK record", e)