from typing import Optional, Any
from database import DBConnectionManager as dbConnect
from utils import logging_utils

def execute_sql(query: str, params: Optional[tuple] = None, should_fetch: bool = False) -> Optional[Any]:
    try:
        result = dbConnect.execute_query(query, params, fetch=should_fetch)
        return result if should_fetch else True
    except Exception as e:
        logging_utils.log_error(f"Error executing query: {query}", e)
        return None

def insert_apk_analysis(analysis_id: int, sha256_hash: str, num_receivers: int, num_activities: int, num_services: int, num_providers: int, num_libraries: int, num_permissions: int, analysis_status: str, additional_info: Optional[str] = None) -> Optional[bool]:
    query = """
    INSERT INTO apk_analysis (analysis_id, sha256_hash, num_receivers, num_activities, num_services, num_providers, num_libraries, num_permissions, analysis_status, additional_info)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    params = (analysis_id, sha256_hash, num_receivers, num_activities, num_services, num_providers, num_libraries, num_permissions, analysis_status, additional_info)
    return execute_sql(query, params)

def insert_vt_applications(analysis_id: int, apk_id: int, package_name: str, main_activity: str, target_sdk_version: int) -> Optional[bool]:
    query = "INSERT INTO vt_applications (analysis_id, apk_id, package_name, main_activity, target_sdk_version) VALUES (%s, %s, %s, %s, %s)"
    params = (analysis_id, apk_id, package_name, main_activity, target_sdk_version)
    return execute_sql(query, params)

def insert_vt_permissions(analysis_id: int, permission_id: int, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_permissions (analysis_id, permission_id, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, permission_id, apk_id)
    return execute_sql(query, params)

def insert_vt_receivers(analysis_id: int, receiver_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_receivers (analysis_id, receiver_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, receiver_name, apk_id)
    return execute_sql(query, params)

def get_next_unknown_permission_permission_id() -> int:
    query = "SELECT MAX(permission_id) FROM unknown_permissions"
    result = execute_sql(query, should_fetch=True)
    if result and result[0][0] is not None:
        return result[0][0] + 1  # Increment the highest permission_id by 1
    else:
        return 1

def insert_unknown_permission(index) -> Optional[bool]:
    # Inserts a new permission record into the 'unknown_permissions'
    # table with details provided in the index object.

    next_permission_id = get_next_unknown_permission_permission_id()
    if not next_permission_id:
        print("Error: Could not retrieve the next permission ID.")
        return None
    
    query = "INSERT INTO unknown_permissions ("
    query += " permission_id, constant_value, protection_level, andro_short_desc, andro_long_desc"
    query += " ) VALUES (%s, %s, %s, %s, %s)"
    params = (next_permission_id,
            index.constant_value,
            index.protection_level,
            index.andro_short_desc,
            index.andro_long_desc)
    
    try:
        result = execute_sql(query, params)
        print(f"Permission {index.constant_value} inserted successfully.")
        return result
    except Exception as e:
        logging_utils.log_error(f"Error inserting unknown permission {index.constant_value}", e)
        return False

def insert_android_permission(permission_name: str) -> Optional[bool]:
    query = "INSERT INTO android_permissions (permission_name, constant_value) VALUES (%s, %s)"
    params = (permission_name, permission_name)  # Using the permission_name for both columns
    return execute_sql(query, params)
