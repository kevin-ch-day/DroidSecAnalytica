# DBFunct_ApkRecords.py

from typing import Optional, List, Dict
from . import db_conn as dbConnect
from utils import logging_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return dbConnect.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def update_apk_record(record_id: int, data: Dict) -> None:
    updates = ", ".join([f"{k} = %s" for k in data.keys()])
    values = list(data.values()) + [record_id]
    query = f"UPDATE apk_samples SET {updates} WHERE apk_id = %s"
    dbConnect.execute_query(query, tuple(values), fetch=False)

def update_malware_ioc_vt_url(id, url):
    query = "UPDATE malware_ioc_threats SET virustotal_url = %s WHERE id = %s"
    return run_query(query, (url, id))

# Update the status of an analysis record
def update_analysis_status(analysis_id: int, status: str):
    query = "UPDATE analysis_metadata SET analysis_status = %s WHERE analysis_id = %s"
    run_query(query, (status, analysis_id), query_type="update")

# Set analysis record status to Completed
def update_status_to_completed(analysis_id: int):
    update_analysis_status(analysis_id, 'Completed')

# Set analysis record status to Failed
def update_status_to_failed(analysis_id: int):
    update_analysis_status(analysis_id, 'Failed')
