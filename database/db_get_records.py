# DBFunct_ApkRecords.py

from typing import Optional, Tuple, List, Dict
from . import db_conn
from utils import logging_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return db_conn.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def get_apk_samples() -> List[Dict]:
    return run_query("SELECT * FROM apk_samples ORDER BY apk_id")

def get_malware_hash_samples() -> List[Dict]:
    return run_query("SELECT * FROM malware_ioc_threats")

def get_apk_id_by_sha256(sha256_hash: str) -> Optional[int]:
    sql = "SELECT apk_id FROM apk_samples WHERE sha256 = %s"
    params = (sha256_hash,)
    result = run_query(sql, params)
    if result:
        return result[0][0]
    else:
        return None

def get_apk_sample_record_by_sha256(sha256) -> List[Dict]:
    return run_query(f"SELECT * FROM apk_samples where sha256 = '{sha256}' ORDER BY apk_id")

def get_samples_id_sha256() -> List[Dict]:
    return run_query("SELECT apk_id, sha256 FROM apk_samples ORDER BY apk_id")

def get_apk_sha256_by_id(apk_id: int) -> Optional[Tuple[int, str]]:
    return next(iter(run_query("SELECT apk_id, sha256 FROM apk_samples WHERE apk_id = %s", (apk_id,))), None)

def get_apk_samples_by_sha256(sha256_list: List[str]) -> List[Dict]:
    # Queries the apk_samples table for records matching a list of SHA256 hashes.
    matching_records = []
    for sha256 in sha256_list:
        records = run_query("SELECT * FROM apk_samples WHERE sha256 = %s", (sha256,))
        if records:
            matching_records.extend(records)
    return matching_records

def get_apk_samples_by_md5(md5_list: List[str]) -> List[Dict]:
    # Queries the apk_samples table for records matching a list of MD5 hashes.
    matching_records = []
    for index in md5_list:
        records = run_query("SELECT * FROM apk_samples WHERE md5 = %s", (index,))
        if records:
            matching_records.extend(records)
    return matching_records

def get_next_unknown_permission_id() -> int:
    # Get the next unknown permission ID
    query = "SELECT MAX(permission_id) FROM unknown_permissions"
    result = run_query(query)
    # Increment and return the next ID or start at 1 if table is empty
    return result[0][0] + 1 if result and result[0][0] is not None else 1

def get_vt_scan_analysis_column_names():
    query = "SHOW COLUMNS FROM vt_scan_analysis"
    column_names = []
    with db_conn.database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        column_names = [column[0] for column in cursor.fetchall()]
    return column_names
