# DBFunctions.py

from typing import Optional, Tuple

from . import DBConnectionManager as dbConnect
from utils import logging_utils

def get_apk_samples():
    query = "SELECT * FROM apk_samples order by apk_id"
    return dbConnect.execute_query(query, fetch=True)

def get_apk_samples_sha256():
    query = "SELECT apk_id, sha256 FROM apk_samples ORDER BY apk_id"
    return dbConnect.execute_query(query, fetch=True)

def get_malware_hash_samples():
    query = "SELECT * FROM malware_ioc_threats"
    return dbConnect.execute_query(query, fetch=True)

def update_apk_record(record_id, data):
    table = "apk_samples"
    condition = "sample_id = %s"
    dbConnect.execute_update(table, data, condition, params=(record_id,))

def get_permission_id_by_name(perm_name):
    query = "SELECT permission_id FROM android_permissions WHERE constant_value = %s"
    params = (perm_name,)
    result = dbConnect.execute_query(query, params, fetch=True)
    return result[0][0] if result else None

def get_unknown_permission_id(perm_name):
    query = "SELECT permission_id FROM unknown_permissions WHERE constant_value = %s"
    params = (perm_name,)
    result = dbConnect.execute_query(query, params, fetch=True)
    return result[0][0] if result else None

def is_unknown_perm_table_empty() -> bool:
    # Checks if the 'unknown_android_permissions' table is empty.
    query = "SELECT COUNT(*) FROM unknown_permissions"
    try:
        result = dbConnect.execute_query(query, fetch=True)
        if result and result[0][0] > 0:
            return False  # Table has records
        else:
            return True  # Table is empty
    except Exception as e:
        logging_utils.log_error("Error checking if 'unknown_android_permissions' table is empty", e)
        return True  # Assume empty in case of error to handle gracefully

def get_apk_record_sha256_by_id(apk_id: int) -> Optional[Tuple[int, str]]:
    query = """
    SELECT a.apk_id, a.sha256
    FROM apk_samples a
    JOIN malware_ioc_threats b ON a.sha256 = b.sha256
    WHERE b.no_virustotal_data IS NULL AND a.apk_id = %s
    ORDER BY a.apk_id ASC
    """
    params = (apk_id,)
    try:
        result = dbConnect.execute_query(query, params, fetch=True)
        if result:
            return result[0]  # Return the first (apk_id, sha256) tuple
        else:
            return None
    except Exception as e:
        logging_utils.log_error(f"Error retrieving record for apk_id {apk_id}", e)
        return None
