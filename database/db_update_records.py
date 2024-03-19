# db_update_records.py

from typing import Optional, List, Dict
from . import db_conn, db_get_records
from utils import logging_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return db_conn.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def update_apk_record(record_id: int, data: Dict) -> None:
    updates = ", ".join([f"{k} = %s" for k in data.keys()])
    values = list(data.values()) + [record_id]
    query = f"UPDATE malware_samples SET {updates} WHERE apk_id = %s"
    db_conn.execute_query(query, tuple(values), fetch=False)

def update_virustotal_report_url(id, url):
    query = "UPDATE malware_samples SET virustotal_url = %s WHERE id = %s"
    return run_query(query, (url, id))

# Update the status of an analysis record
def update_analysis_status(analysis_id: int, status: str):
    query = "UPDATE analysis_metadata SET analysis_status = %s WHERE analysis_id = %s"
    run_query(query, (status, analysis_id))

# Function to create vt_scan_analysis record
def update_vt_engine_column(analysis_id: int, detections: list):
    # Fetch and prepare the column names.
    column_names = db_get_records.get_vt_scan_analysis_columns()
    valid_columns = {col.replace('_', '-'): col for col in column_names}  # Reverse mapping for normalization.

    for detection in detections:
        av_vendor, result = detection
        # Normalize AV vendor names to match column names, considering the reverse mapping.
        column_name = valid_columns.get(av_vendor)

        if column_name:
            sql = f"UPDATE vt_scan_analysis SET `{column_name}` = %s WHERE analysis_id = %s"
            params = (result, analysis_id)
            try:
                with db_conn.database_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(sql, params)
                    conn.commit()
            except Exception as e:
                logging_utils.log_error(f"Error updating record for {av_vendor} in analysis {analysis_id}", e)
        else:
            logging_utils.log_error(f"Invalid AV vendor name: {av_vendor}")

def update_vt_engine_detection_metadata(analysis_id: int, summary_stat: dict):
    with db_conn.database_connection() as conn:
        cursor = conn.cursor()
        for key, value in summary_stat.items():
            # Replace hyphens in key names with underscores to match column names
            column_name = key.replace('-', '_')
            # Construct the SQL UPDATE statement for each modified key-value pair
            sql = f"UPDATE vt_scan_analysis SET `{column_name}` = %s WHERE analysis_id = %s"
            params = (value, analysis_id)
            try:
                cursor.execute(sql, params)
                conn.commit()
            except Exception as e:
                logging_utils.log_error(f"Error updating {column_name} for analysis_id {analysis_id}", e)

def update_analysis_metadata(id: int, sha256: str, package_name: str, main_activity: str, min_sdk: int, target_sdk: int) -> Optional[bool]:
    query = """
    UPDATE analysis_metadata
    SET sha256_hash = %s,
        package_name = %s,
        main_activity = %s,
        target_min_version = %s,
        target_sdk_version = %s
    WHERE analysis_id = %s;
    """
    params = (sha256, package_name, main_activity, min_sdk, target_sdk, id)
    return run_query(query, params)

def update_analysis_metadata_column(analysis_id: int, column_name: str, column_value: int) -> Optional[bool]:
    query = f"UPDATE analysis_metadata SET {column_name} = %s WHERE analysis_id = %s"
    params = (column_value, analysis_id)
    return run_query(query, params)
