# DBTableManagement.py

from utils import logging_utils
from . import DBConnectionManager as dbConnect

# Executes a SQL query and returns the results or None if should_fetch is False
def execute_sql(query: str, params: tuple = None, should_fetch: bool = False):
    try:
        return dbConnect.execute_query(query, params, fetch=should_fetch)
    except Exception as e:
        logging_utils.log_error(f"Error executing query: {query}", e)
        return None if should_fetch else False

# Checks if a specific table exists in the database
def check_for_table(table_name: str) -> bool:
    return bool(execute_sql("SHOW TABLES LIKE %s;", (table_name,), True))

# Lists all tables in the database with their column and row counts
def list_tables() -> list:
    result = execute_sql("SHOW TABLES;", should_fetch=True)
    if not result:
        return []

    table_info = []
    for (table_name,) in result:
        num_columns = len(execute_sql(f"SHOW COLUMNS FROM {table_name};", should_fetch=True))
        num_rows = execute_sql(f"SELECT COUNT(*) FROM {table_name};", should_fetch=True)[0][0]
        table_info.append((table_name, num_columns, num_rows))
    return table_info

# Creates a table for storing Android malware hashes
def create_android_malware_hash_table() -> bool:
    sql_create_table = """
        CREATE TABLE IF NOT EXISTS android_malware_threat_metadata (
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
    success = execute_sql(sql_create_table, should_fetch=False)
    if success:
        print("Table 'android_malware_threat_metadata' created successfully.")
    return success

# Updates a record in android_malware_threat_metadata to indicate no VirusTotal match
def no_virustotal_record_match(record_id):
    if execute_sql("UPDATE android_malware_threat_metadata SET no_virustotal_match = 1 WHERE id = %s", (record_id,)):
        print("Database record updated.")

# Creates a record for an APK sample
def create_apk_record(filename: str, filesize: int, md5: str, sha1: str, sha256: str):
    sql = "INSERT INTO apk_samples (filename, filesize, md5, sha1, sha256) VALUES (%s, %s, %s, %s, %s)"
    if execute_sql(sql, (filename, filesize, md5, sha1, sha256)):
        logging_utils.log_info("APK record created successfully.")
