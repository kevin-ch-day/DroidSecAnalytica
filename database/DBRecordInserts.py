from typing import Optional, Any
from database import DBConnectionManager as dbConnect
from utils import logging_utils

def execute_sql(query: str, params: Optional[tuple] = None, should_fetch: bool = False) -> Optional[Any]:
    try:
        # Using execute_query from DBConnectionManager, assuming it's the correct function based on DBConnectionManager content
        result = dbConnect.execute_query(query, params, fetch=should_fetch)
        return result
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

def insert_unknown_permission(permission_name: str) -> Optional[bool]:
    query = "INSERT INTO unknown_android_permissions (constant_value) VALUES (%s)"
    params = (permission_name,)
    return execute_sql(query, params)
