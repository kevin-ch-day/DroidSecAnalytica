# DBFunct_AnalysisRecords.py

from typing import Optional, Tuple, List, Dict
from . import DBConnectionManager as dbConnect
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
        logging_utils.log_error("Failed to execute query: {} with params: {}".format(sql, params), e)
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

# Update the status of an analysis record
def update_analysis_status(analysis_id: int, status: str):
    query = "UPDATE analysis_metadata SET analysis_status = %s WHERE analysis_id = %s"
    run_query(query, (status, analysis_id), query_type="update")

# Set analysis record status to Completed
def update_analysis_status_to_completed(analysis_id: int):
    update_analysis_status(analysis_id, 'Completed')

# Set analysis record status to Failed
def update_analysis_status_to_failed(analysis_id: int):
    update_analysis_status(analysis_id, 'Failed')
