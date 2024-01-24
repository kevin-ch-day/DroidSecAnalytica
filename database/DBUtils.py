# DBUtils.py

from typing import List, Dict, Optional
from utils import logging_utils
from . import DBConnectionManager as dbConnect

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
