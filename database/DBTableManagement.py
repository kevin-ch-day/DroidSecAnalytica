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

# Updates a record in android_malware_threat_metadata to indicate no VirusTotal match
def no_virustotal_record_match(record_id):
    if execute_sql("UPDATE android_malware_threat_metadata SET no_virustotal_match = 1 WHERE id = %s", (record_id,)):
        print("Database record updated.")

# Creates a record for an APK sample
def create_apk_record(filename: str, filesize: int, md5: str, sha1: str, sha256: str):
    sql = "INSERT INTO apk_samples (filename, filesize, md5, sha1, sha256) VALUES (%s, %s, %s, %s, %s)"
    if execute_sql(sql, (filename, filesize, md5, sha1, sha256)):
        logging_utils.log_info("APK record created successfully.")

def truncate_analysis_data_tables() -> bool:
    table_names = [
        "analysis_metadata",
        "vt_activities",
        "vt_certificates",
        "vt_libraries",
        "vt_permissions",
        "vt_receivers",
        "vt_scan_analysis",
        "vt_services",
        "apk_analysis"
    ]
    
    try:
        for table_name in table_names:
            execute_sql(f"TRUNCATE TABLE {table_name}")
            print(f"Successfully truncated table: {table_name}")

        print("All specified tables were successfully truncated.")
        return True
    
    except Exception as e:
        logging_utils.log_error("An error occurred while truncating tables. Transaction has been rolled back.", e)
        return False
