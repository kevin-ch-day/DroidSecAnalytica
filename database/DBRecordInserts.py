# DBRecordInserts.py

from typing import Optional
from database import DBConnectionManager as dbConnect
from utils import logging_utils

# Execute SQL queries
def execute_sql(query: str, params: Optional[tuple] = None, should_fetch: bool = False) -> Optional[any]:
    try:
        result = dbConnect.execute_query(query, params, fetch=should_fetch)
        return result if should_fetch else True
    except Exception as e:
        logging_utils.log_error(f"Error executing query: {query}", e)
        return None

# Function to insert data into vt_permissions table
def insert_vt_permissions(analysis_id: int, apk_id: int, known_permission_id: Optional[int], unknown_permission_id: Optional[int]) -> Optional[bool]:
    query = "INSERT INTO vt_permissions (analysis_id, apk_id, known_permission_id, unknown_permission_id)"
    query += " VALUES (%s, %s, %s, %s)"
    params = (analysis_id, apk_id, known_permission_id, unknown_permission_id)
    return execute_sql(query, params)

def insert_vt_activities(analysis_id: int, activity_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_activities (analysis_id, activity_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, activity_name, apk_id)
    return execute_sql(query, params)

def insert_vt_libraries(analysis_id: int, library_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_libraries (analysis_id, library_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, library_name, apk_id)
    return execute_sql(query, params)

def insert_vt_services(analysis_id: int, service_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_services (analysis_id, service_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, service_name, apk_id)
    return execute_sql(query, params)

def insert_vt_receivers(analysis_id: int, receiver_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_receivers (analysis_id, receiver_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, receiver_name, apk_id)
    return execute_sql(query, params)

# Get the next unknown permission ID
def get_next_unknown_permission_id() -> int:
    query = "SELECT MAX(permission_id) FROM unknown_permissions"
    result = execute_sql(query, should_fetch=True)
    # Increment and return the next ID or start at 1 if table is empty
    return result[0][0] + 1 if result and result[0][0] is not None else 1

# Insert a new unknown permission record
def insert_unknown_permission(index) -> Optional[bool]:
    id = get_next_unknown_permission_id()
    if not id:
        # Handle error if next permission ID could not be retrieved
        print("Error: Could not retrieve the next permission ID.")
        return None
    query = "INSERT INTO unknown_permissions (permission_id, constant_value, protection_level, andro_short_desc, andro_long_desc) VALUES (%s, %s, %s, %s, %s)"
    params = (id, index.name, index.permission_type, index.short_desc, index.long_desc)
    return execute_sql(query, params)

# Insert a new android permission record more concisely
def insert_android_permission_v2(constant_value: str) -> Optional[bool]:
    # Extract permission name by splitting the constant value and taking the last part
    # This handles cases with or without the "android.permission." prefix
    permission_name = constant_value.split('.')[-1]
    query = "INSERT INTO android_permissions (permission_name, constant_value) VALUES (%s, %s)"
    params = (permission_name, constant_value)
    return execute_sql(query, params)

# Create a new apk_analysis record
def create_apk_analysis_records(id: int, sha256: str, package_name: str, main_activity: str, target_sdk: int) -> Optional[bool]:
    query = """
    INSERT INTO apk_analysis (analysis_id, sha256_hash, package_name, main_activity, target_sdk_version)
    VALUES (%s, %s, %s, %s, %s)
    """
    params = (id, sha256, package_name, main_activity, target_sdk)
    return execute_sql(query, params)

# Update counts in apk_analysis table
def update_apk_analysis_counts(analysis_id: int, receivers: int, activities: int, services: int, libraries: int) -> Optional[bool]:
    query = """
    UPDATE apk_analysis SET num_receivers = %s, num_activities = %s, num_services = %s, num_libraries = %s
    WHERE analysis_id = %s
    """
    params = (receivers, activities, services, libraries, analysis_id)
    return execute_sql(query, params)
