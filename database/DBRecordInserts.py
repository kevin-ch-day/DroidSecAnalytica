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

# Function to create vt_scan_analysis record
def create_vt_engine_record(analysis_id: int, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_scan_analysis (analysis_id, apk_id)"
    query += " VALUES (%s, %s)"
    params = (analysis_id, apk_id)
    return execute_sql(query, params)

def update_vt_engine_detection(analysis_id: int, summary_stat: dict):
    with dbConnect.database_connection() as conn:
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

def fetch_vt_scan_analysis_column_names():
    query = "SHOW COLUMNS FROM vt_scan_analysis"
    column_names = []
    with dbConnect.database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        column_names = [column[0] for column in cursor.fetchall()]
    return column_names

# Function to create vt_scan_analysis record
def update_vt_engine_records(analysis_id: int, detections: list):
    # Fetch and prepare the column names.
    column_names = fetch_vt_scan_analysis_column_names()
    valid_columns = {col.replace('_', '-'): col for col in column_names}  # Reverse mapping for normalization.

    for detection in detections:
        av_vendor, result = detection
        # Normalize AV vendor names to match column names, considering the reverse mapping.
        column_name = valid_columns.get(av_vendor)

        if column_name:
            sql = f"UPDATE vt_scan_analysis SET `{column_name}` = %s WHERE analysis_id = %s"
            params = (result, analysis_id)
            try:
                with dbConnect.database_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(sql, params)
                    conn.commit()
            except Exception as e:
                logging_utils.log_error(f"Error updating record for {av_vendor} in analysis {analysis_id}", e)
        else:
            logging_utils.log_error(f"Invalid AV vendor name: {av_vendor}")

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
    params = (id, index.name, index.permission_type, index.short_desc, index.long_desc)
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
    query = "INSERT INTO vt_receivers (analysis_id, provider_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, provider_name, apk_id)
    return execute_sql(query, params)

# Get the next unknown permission ID
def get_next_unknown_permission_id() -> int:
    query = "SELECT MAX(permission_id) FROM unknown_permissions"
    result = execute_sql(query, should_fetch=True)
    # Increment and return the next ID or start at 1 if table is empty
    return result[0][0] + 1 if result and result[0][0] is not None else 1

# Create a new apk_analysis record
def create_apk_analysis_records(id: int, sha256: str, package_name: str, main_activity: str, min_sdk: int , target_sdk: int) -> Optional[bool]:
    query = """
    INSERT INTO apk_analysis (
            analysis_id,
            sha256_hash,
            package_name,
            main_activity,
            target_min_version,
            target_sdk_version)
    VALUES (%s, %s, %s, %s, %s , %s)
    """
    params = (id, sha256, package_name, main_activity, min_sdk, target_sdk)
    return execute_sql(query, params)

# Update counts in apk_analysis table
def update_apk_analysis_counts(analysis_id: int, receivers: int, activities: int, services: int, libraries: int) -> Optional[bool]:
    query = """
    UPDATE apk_analysis
        SET num_receivers = %s,
        num_activities = %s,
        num_services = %s,
        num_libraries = %s
    WHERE analysis_id = %s
    """
    params = (receivers, activities, services, libraries, analysis_id)
    return execute_sql(query, params)

def create_apk_sample_record(file_name, file_size, md5, sha1, sha256):
    query = """
    INSERT INTO apk_samples (file_name, file_size, md5, sha1, sha256)
    VALUES (%s, %s, %s, %s, %s)
    """
    return execute_sql(query, (file_name, file_size, md5, sha1, sha256))
