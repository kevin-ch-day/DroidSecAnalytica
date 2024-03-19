# db_create_records.py

from typing import Optional, List, Dict
from . import db_conn as dbConnect
from utils import logging_utils

# Function to execute SQL queries with optional parameters and distinguish query types
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

# Creates a new analysis record
def create_analysis_record(analysis_name: str):
    query = "SELECT MAX(analysis_id) AS max_id FROM analysis_metadata"
    result_max_id = run_query(query)

    # Check if result_max_id is not empty and then extract the max_id
    max_id = result_max_id[0][0] if result_max_id and result_max_id[0][0] is not None else 0
    next_id = max_id + 1
    
    query = "INSERT INTO analysis_metadata (analysis_id, analysis_name, analysis_status) VALUES (%s, %s, %s)"
    params = (next_id, analysis_name, 'InProgress')
    run_query(query, params, query_type="insert")
    return next_id

# Create a new apk_analysis record
def create_apk_analysis_records(id: int, sha256: str, package_name: str, main_activity: str, min_sdk: int , target_sdk: int) -> Optional[bool]:
    query = """
    INSERT INTO apk_analysis (
            analysis_id,
            sha256_hash,
            package_name,
            main_activity,
            target_min_version,
            target_sdk_version)
    VALUES (%s, %s, %s, %s, %s , %s)
    """
    params = (id, sha256, package_name, main_activity, min_sdk, target_sdk)
    return run_query(query, params)

def create_apk_sample_record(file_name, file_size, md5, sha1, sha256):
    query = """
    INSERT INTO apk_samples (file_name, file_size, md5, sha1, sha256)
    VALUES (%s, %s, %s, %s, %s)
    """
    return run_query(query, (file_name, file_size, md5, sha1, sha256))

# Creates a new analysis record
def create_analysis_record(analysis_name: str):
    query = "SELECT MAX(analysis_id) AS max_id FROM analysis_metadata"
    result_max_id = run_query(query)

    # Check if result_max_id is not empty and then extract the max_id
    max_id = result_max_id[0][0] if result_max_id and result_max_id[0][0] is not None else 0
    next_id = max_id + 1
    
    query = "INSERT INTO analysis_metadata (analysis_id, analysis_name, analysis_status) VALUES (%s, %s, %s)"
    params = (next_id, analysis_name, 'InProgress')
    run_query(query, params, query_type="insert")
    return next_id

# Function to create vt_scan_analysis record
def create_vt_engine_record(analysis_id: int, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_scan_analysis (analysis_id, apk_id)"
    query += " VALUES (%s, %s)"
    params = (analysis_id, apk_id)
    return run_query(query, params)
