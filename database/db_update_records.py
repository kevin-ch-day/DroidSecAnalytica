# db_update_records.py

from typing import Optional, List, Dict
from . import db_conn, db_get_records, db_create_records
from utils import logging_utils

logger = logging_utils.get_logger(__name__)

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return db_conn.execute_query(sql, params, fetch=True) or []
    except Exception:
        logger.exception("Error executing SQL query: %s", sql)
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

def update_analysis_metadata(id: int, sha256: str, package_name: str, main_activity: str, min_sdk: int, target_sdk: int) -> Optional[bool]:
    query = """
    UPDATE analysis_metadata
    SET sha256 = %s,
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

def update_analysis_classification(id: int, label: str) -> Optional[bool]:
    query = "UPDATE analysis_metadata SET sample_classification = %s WHERE analysis_id = %s"
    params = (label, id)
    return run_query(query, params)

# Function to update a record in the hash_data_ioc table with all hash data
def update_hash_data_ioc_record(md5: Optional[str], sha1: Optional[str], sha256: Optional[str]) -> Optional[bool]:
    # Check if any of the hash types are provided
    if not (md5, sha1, sha256):
        print("[ERROR] No valid hash values provided.")
        return None

    # Query to find the existing record based on any of the hash values
    query_find = "SELECT id, md5, sha1, sha256 FROM hash_data_ioc WHERE md5 = %s OR sha1 = %s OR sha256 = %s"
    params_find = (md5, sha1, sha256)

    # Execute the query to find the record
    try:
        # Assuming run_query returns a list of tuples (e.g., [(1, 'md5', 'sha1', 'sha256')])
        records = run_query(query_find, params_find)

        # If no record is found
        if not records:
            return None

        # If more than one record is found, display the records and exit
        if len(records) > 1:
            print("[WARNING] Multiple matching records found:")
            for rec in records:
                print(f"Record ID: {rec[0]}, MD5: {rec[1]}, SHA1: {rec[2]}, SHA256: {rec[3]}")
            print("[ERROR] Multiple records found. Update operation aborted.")
            return None

        # Access the first record and the first column (ID) using integer indices
        record_id = records[0][0]

        # Query to update the found record with all the provided hash data
        query_update = """
            UPDATE hash_data_ioc
            SET md5 = IFNULL(%s, md5),
                sha1 = IFNULL(%s, sha1),
                sha256 = IFNULL(%s, sha256)
            WHERE id = %s
        """
        params_update = (md5, sha1, sha256, record_id)

        # Execute the query to update the record
        run_query(query_update, params_update)
        return True

    except Exception as e:
        print(f"[ERROR] Failed to update record: {e}")
        return None

def update_kaspersky_not_a_virus(apk_id: int, is_not_a_virus: bool) -> Optional[bool]:
    # Set the value for the update based on the boolean input
    if not is_not_a_virus:
        column_status = 0
    else:
        column_status = 1

    query_update = """
        UPDATE vt_scan_analysis
        SET Kaspersky_not_a_virus = %s
        WHERE apk_id = %s
    """
    params_update = (column_status, apk_id)

    try:
        run_query(query_update, params_update)
        return True

    except Exception as e:
        print(f"[ERROR] Failed to update 'Kaspersky_not_a_virus' for apk_id {apk_id}: {e}")
        return None
    
def update_zoneAlarm_not_a_virus(apk_id: int, is_not_a_virus: bool) -> Optional[bool]:
    # Set the value for the update based on the boolean input
    if not is_not_a_virus:
        column_status = 0
    else:
        column_status = 1

    query_update = """
        UPDATE vt_scan_analysis
        SET ZoneAlarm_not_a_virus = %s
        WHERE apk_id = %s
    """
    params_update = (column_status, apk_id)

    try:
        run_query(query_update, params_update)
        return True

    except Exception as e:
        print(f"[ERROR] Failed to update 'ZoneAlarm_not_a_virus' for apk_id {apk_id}: {e}")
        return None

def update_malware_type_description(sha256: str, data_type_description: str) -> Optional[bool]:
    # Update the data_type_description in the malware_samples table for a given sha256 hash.

    query = """
        UPDATE malware_samples
        SET data_type_description = %s
        WHERE sha256 = %s
    """
    params = (data_type_description, sha256)

    try:
        result = run_query(query, params)
        return True if result else False  # Return True if updated, False if no rows were affected
    except Exception:
        logger.exception("Error updating data_type_description for SHA256 %s", sha256)
        return None
