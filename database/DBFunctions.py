# DBFunctions.py

from typing import Optional, Tuple, List

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

def get_apk_records_sha256(apk_id: Optional[int] = None) -> Optional[List[Tuple[int, str]]]:
    query = """
    SELECT a.apk_id, a.sha256
    FROM apk_samples a
    JOIN malware_ioc_threats b ON a.sha256 = b.sha256
    WHERE b.no_virustotal_data IS NULL
    """
    params = ()
    if apk_id is not None:
        query += " AND a.apk_id >= %s"
        params = (apk_id,)

    query += " ORDER BY a.apk_id ASC"

    try:
        result = dbConnect.execute_query(query, params, fetch=True)
        if result:
            return result
        else:
            return None
    except Exception as e:
        logging_utils.log_error(f"Error retrieving records", e)
        return None

def get_apk_record_sha256_by_id(apk_id: int) -> Optional[Tuple[int, str]]:
    query = """
    SELECT a.apk_id, a.sha256
    FROM apk_samples a
    JOIN malware_ioc_threats b ON a.sha256 = b.sha256
    WHERE b.no_virustotal_data IS NULL AND a.apk_id = %s
    ORDER BY a.apk_id ASC
    """
    params = (apk_id,)  # Keep apk_id as an int, the database driver handles conversion
    try:
        result = dbConnect.execute_query(query, params, fetch=True)
        if result:
            return result[0]  # Return the first (apk_id, sha256) tuple
        else:
            return None
    except Exception as e:
        logging_utils.log_error(f"Error retrieving record for apk_id {apk_id}", e)
        return None

def check_unknown_permissions_duplicates() -> Optional[List[Tuple[str, int]]]:
    query = """
    SELECT constant_value, GROUP_CONCAT(permission_id) as permission_ids
    FROM unknown_permissions
    GROUP BY constant_value
    HAVING COUNT(permission_id) > 1
    """
    try:
        result = dbConnect.execute_query(query, fetch=True)
        if result:
            non_unique_values = [(row[0], row[1]) for row in result]
            for value, ids in non_unique_values:
                print(f"Non-unique constant_value: {value}, Permission IDs: {ids}")
            return non_unique_values
        else:
            print("No non-unique constant_values found.")
            return None
    except Exception as e:
        logging_utils.log_error("Error finding non-unique constant_values", e)
        return None

def check_uknown_permissions_alpha() -> Optional[List[Tuple[int, str]]]:
    query = "SELECT permission_id, constant_value FROM unknown_permissions"
    query += " WHERE constant_value LIKE 'android.permission.%' order by constant_value"
    try:
        result = dbConnect.execute_query(query, fetch=True)
        if result:
            permissions = [(row[0], row[1]) for row in result]
            return permissions
        else:
            print("No permissions found matching 'android.permission.*' format.")
            return None
    except Exception as e:
        logging_utils.log_error("Error retrieving 'android.permission.*' formatted permissions", e)
        return None