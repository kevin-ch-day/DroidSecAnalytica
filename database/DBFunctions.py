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
    query = "SELECT a.apk_id, a.sha256 FROM apk_samples a"
    query += " JOIN malware_ioc_threats b ON a.sha256 = b.sha256"
    query += " WHERE b.no_virustotal_data IS NULL"

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
    query = "SELECT constant_value, GROUP_CONCAT(permission_id) as permission_ids"
    query += " FROM unknown_permissions GROUP BY constant_value HAVING COUNT(permission_id) > 1"

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
    
# Executes a SQL query and returns the results.
def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return dbConnect.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

# Retrieves intent filters based on their unusual status.
def get_intent_filters(is_unusual: bool = True) -> List[Dict]:
    sql = "SELECT * FROM android_intent_filters WHERE IsUnusual = %s"
    params = (1 if is_unusual else 0,)
    return run_query(sql, params)

# Retrieves a specific intent filter record by its name.
def get_intent_filter_record_by_name(intent_name: str) -> Optional[Dict]:
    sql = "SELECT * FROM android_intent_filters WHERE IntentName = %s"
    return next(iter(run_query(sql, (intent_name,))), None)

# Retrieves all permissions from the android_permissions table.
def get_all_permissions() -> List[Dict]:
    return run_query("SELECT * FROM android_permissions;")

# Retrieves permissions filtered by a specific category.
def get_permissions_by_category(category: str) -> List[Dict]:
    return run_query("SELECT * FROM android_permissions WHERE category = %s", (category,))

# Searches for permissions by name or description.
def search_permission(search_term: str) -> List[Dict]:
    query = "SELECT * FROM android_permissions WHERE permission_name LIKE %s OR description LIKE %s"
    search_query = f"%{search_term}%"
    return run_query(query, (search_query, search_query))

# Retrieves all services from the android_services table.
def get_all_services() -> List[Dict]:
    return run_query("SELECT * FROM android_services;")

# Searches for services by name.
def search_services_by_name(service_name: str) -> List[Dict]:
    query = "SELECT * FROM android_services WHERE ServiceName LIKE %s"
    search_query = f"%{service_name}%"
    return run_query(query, (search_query,))

# Retrieves services marked as malware-prone.
def get_malware_prone_services() -> List[Dict]:
    return run_query("SELECT * FROM android_services WHERE IsMalwareProne = 1")

def create_analysis_record(analysis_name):
    insert_query = """
    INSERT INTO analysis_metadata (analysis_name, analysis_status)
    VALUES (%s, 'InProgress')
    """
    try:
        analysis_id = dbConnect.execute_query(insert_query, (analysis_name,), fetch=True)
        if analysis_id:
            analysis_id_value = analysis_id[0][0]  # Assuming the first row and first column is the ID
            logging_utils.log_info(f"Analysis record created with ID: {analysis_id_value}")
            return analysis_id_value
    except Exception as e:
        logging_utils.log_error("Error creating analysis record", e)
    return None

def update_analysis_status(analysis_id, status):
    update_query = """
    UPDATE analysis_metadata
    SET analysis_status = %s
    WHERE analysis_id = %s
    """
    try:
        dbConnect.execute_query(update_query, (status, analysis_id), fetch=False)
        logging_utils.log_info(f"Analysis status updated to '{status}' for ID: {analysis_id}")
    except Exception as e:
        logging_utils.log_error(f"Error updating analysis status to '{status}'", e)

def update_analysis_status_to_completed(analysis_id):
    update_analysis_status(analysis_id, 'Completed')

def update_analysis_status_to_failed(analysis_id):
    update_analysis_status(analysis_id, 'Failed')

def reorder_unknown_permissions():
    with dbConnect.database_connection() as conn:
        cursor = conn.cursor()
        # Step 1: Temporarily increase permission_id by an offset to avoid PRIMARY key conflict
        offset = 90000  # Use an offset larger than the current max permission_id in the table
        cursor.execute("UPDATE unknown_permissions SET permission_id = permission_id + %s", (offset,))

        # Step 2: Fetch all permissions with the temporary offset, ordered by your criteria (e.g., constant_value)
        cursor.execute("SELECT permission_id FROM unknown_permissions ORDER BY constant_value ASC")
        permissions = cursor.fetchall()

        # Step 3: Reset permission_id to sequential order starting from 1
        new_id = 1
        for (temp_permission_id,) in permissions:
            cursor.execute("UPDATE unknown_permissions SET permission_id = %s WHERE permission_id = %s", (new_id, temp_permission_id))
            new_id += 1
        conn.commit()
        print("Unknow Permissions reordered successfully.")