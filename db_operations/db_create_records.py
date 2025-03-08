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
