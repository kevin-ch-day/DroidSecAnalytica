# db_create_records.py

from typing import Optional, List, Dict
from . import db_conn as dbConnect
from utils import logging_utils

# Execute SQL queries with optional parameters and distinguish query types
def run_query(sql: str, params: Optional[tuple] = None, query_type: str = "select"):
    try:
        if query_type == "select":
            results = dbConnect.execute_query(sql, params, fetch=True)
            return results if results else []
        else:
            dbConnect.execute_query(sql, params, fetch=False)
            return [{"status": "success"}]
    except Exception as e:
        logging_utils.log_error(f"Failed to execute query: {sql} with params: {params}", e)
        return []

def create_malware_record(file_name, family, md5, sha1, sha256, file_size):
    query = """
    INSERT INTO malware_samples (name, family, md5, sha1, sha256, file_size)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    return run_query(query, (file_name, family, md5, sha1, sha256, file_size))

# Creates a new analysis record, handling cases where there are no existing IDs.
def create_analysis_record(sample_type: str):
    query = "SELECT MAX(analysis_id) FROM analysis_metadata"
    results = run_query(query)
    
    # If no results, start with ID 1; otherwise, increment the max ID
    current_max_id = results[0][0] if results and results[0][0] is not None else 0
    next_id = current_max_id + 1  # Ensure next ID is always valid
    query = "INSERT INTO analysis_metadata (analysis_id, analysis_status, sample_type) VALUES (%s, %s, %s)"
    params = (next_id, 'InProgress', sample_type)

    run_query(query, params, query_type="insert")
    
    return next_id


# Function to create vt_scan_analysis record
def create_vt_engine_record(analysis_id: int, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_scan_analysis (analysis_id, apk_id)"
    query += " VALUES (%s, %s)"
    params = (analysis_id, apk_id)
    return run_query(query, params)

def create_vt_engine_column(new_vt_engine, data_type="VARCHAR(100)"):
    # Ensure the new column name is valid: it must be a non-empty string
    if not isinstance(new_vt_engine, str) or not new_vt_engine.strip():
        raise ValueError("Invalid vt engine name. The name must be a non-empty string.")
    
    try:
        # Check if the column already exists in the `vt_scan_analysis` table
        existing_columns = run_query("SHOW COLUMNS FROM vt_scan_analysis", query_type="select")
        
        # If the new column name matches any existing column name, raise an error
        if any(col[0] == new_vt_engine for col in existing_columns):
            raise ValueError(f"Column: '{new_vt_engine}' already exists.")
        
        # Prepare the SQL query to add the new column with the specified data type
        # The new column is added after the `type_unsupported` column in the table
        sql = f"ALTER TABLE vt_scan_analysis ADD COLUMN {new_vt_engine} {data_type} AFTER type_unsupported;"
        run_query(sql)
        
        print(f"New vt_engine column \"{new_vt_engine}\" added successfully.")
    
    except Exception as e:
        # If an error occurs, print an error message with the details
        print(f"Failed to add new vt_engine column \"{new_vt_engine}\": {e}")


def create_malware_project_mapping(malware_id, droidsecanalytica, family, md5):
    report_id = 0
    classification = droidsecanalytica
    
    try:
        sql = "UPDATE malware_project_mapping SET droidsecanalytica_label = %s WHERE malware_id = %s;"
        params = (malware_id, report_id, droidsecanalytica, family, md5)
        run_query(sql, params=params, fetch=False)

    except Exception as e:
        print(f"Failed to update malware_project_mapping for malware id: {malware_id}")
        print(f"Exception: {e}")
