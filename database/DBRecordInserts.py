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

# Insert into permissions table
def insert_vt_permissions(analysis_id: int, permission_id: int, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_permissions (analysis_id, permission_id, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, permission_id, apk_id)
    return execute_sql(query, params)

# Insert into receivers table
def insert_vt_receivers(analysis_id: int, receiver_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_receivers (analysis_id, receiver_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, receiver_name, apk_id)
    return execute_sql(query, params)

# Get the number unknown permission id 
def get_next_unknown_permission_id() -> int:
    query = "SELECT MAX(permission_id) FROM unknown_permissions"
    result = execute_sql(query, should_fetch=True)
    if result and result[0][0] is not None:
        return result[0][0] + 1 
    else:
        return 1

def insert_unknown_permission(index) -> Optional[bool]:
    # Inserts a new permission record into the 'unknown_permissions'
    id = get_next_unknown_permission_id()
    if not id:
        print("Error: Could not retrieve the next permission ID.")
        return None
    
    query = "INSERT INTO unknown_permissions ("
    query += " permission_id, constant_value, protection_level, andro_short_desc, andro_long_desc"
    query += " ) VALUES (%s, %s, %s, %s, %s)"
    params = (id, index.name, index.permission_type, index.short_desc, index.long_desc)
    
    try:
        result = execute_sql(query, params)
        return result
    except Exception as e:
        logging_utils.log_error(f"Error inserting unknown permission {index.name}", e)
        return False

def insert_android_permission(constant_value: str) -> Optional[bool]:
    prefix = "android.permission."
    if constant_value.startswith(prefix):
        permission_name = constant_value[len(prefix):]
    else:
        permission_name = constant_value
    query = "INSERT INTO android_permissions (permission_name, constant_value) VALUES (%s, %s)"
    params = (permission_name, constant_value)
    return execute_sql(query, params)

def create_apk_analysis_records(id: int, sha256: str, package_name: str, main_activity: str, target_sdk: int) -> Optional[bool]:
    query = """
    INSERT INTO apk_analysis (analysis_id, sha256_hash, package_name, main_activity, target_sdk_version)
    VALUES (%s, %s, %s, %s, %s)
    """
    params = (id, sha256, package_name, main_activity, target_sdk)
    return execute_sql(query, params)

def update_apk_analysis_counts(analysis_id: int, receivers: int, activities: int, services: int, libraries: int) -> Optional[bool]:
    query = """
    UPDATE apk_analysis
    SET num_receivers = %s, num_activities = %s, num_services = %s, num_libraries = %s
    WHERE analysis_id = %s
    """
    params = (receivers, activities, services, libraries, analysis_id)
    return execute_sql(query, params)