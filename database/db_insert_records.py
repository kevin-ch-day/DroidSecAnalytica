# db_insert_records.py

from typing import Optional
from database import db_conn as dbConnect
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
def insert_vt_permission(analysis_id: int, apk_id: int, known_permission_id: Optional[int], unknown_permission_id: Optional[int]) -> Optional[bool]:
    query = "INSERT INTO vt_permissions (analysis_id, apk_id, known_permission_id, unknown_permission_id)"
    query += " VALUES (%s, %s, %s, %s)"
    params = (analysis_id, apk_id, known_permission_id, unknown_permission_id)
    return execute_sql(query, params)

# Insert a new unknown permission record
def insert_unknown_permission(index) -> Optional[bool]:
    id = get_next_unknown_permission_id()
    if not id:
        print("Error: Could not retrieve the next permission ID.")
        return None
    
    query = "INSERT INTO unknown_permissions (permission_id, constant_value, protection_level, andro_short_desc, andro_long_desc) VALUES (%s, %s, %s, %s, %s)"
    params = (id, index.name, index.
              
              permission_type, index.short_desc, index.long_desc)
    return execute_sql(query, params)

# Insert a new android permission record more concisely
def insert_android_permission_v2(constant_value: str) -> Optional[bool]:
    # This handles cases with or without the "android.permission." prefix
    permission_name = constant_value.split('.')[-1]
    query = "INSERT INTO android_permissions (permission_name, constant_value) VALUES (%s, %s)"
    params = (permission_name, constant_value)
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

def insert_vt_providers(analysis_id: int, provider_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_providers (analysis_id, provider_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, provider_name, apk_id)
    return execute_sql(query, params)