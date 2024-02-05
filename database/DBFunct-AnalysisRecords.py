# DBFunctions.py

from typing import Optional, Tuple, List, Dict
from . import DBConnectionManager as dbConnect
from utils import logging_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return dbConnect.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def create_analysis_record(analysis_name: str) -> Optional[int]:
    result = run_query("INSERT INTO analysis_metadata (analysis_name, analysis_status) VALUES (%s, 'InProgress') RETURNING analysis_id", (analysis_name,))
    return result[0]['analysis_id'] if result else None

def update_analysis_status(analysis_id: int, status: str) -> None:
    run_query("UPDATE analysis_metadata SET analysis_status = %s WHERE analysis_id = %s", (status, analysis_id))

def update_analysis_status_to_completed(analysis_id: int) -> None:
    update_analysis_status(analysis_id, 'Completed')

def update_analysis_status_to_failed(analysis_id: int) -> None:
    update_analysis_status(analysis_id, 'Failed')
