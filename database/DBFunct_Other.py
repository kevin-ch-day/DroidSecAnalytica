# DBFunctions.py

from typing import Optional, Tuple, List, Dict
from . import DBConnectionManager as dbConnect
from utils import logging_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return dbConnect.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def get_intent_filters(is_unusual: bool = True) -> List[Dict]:
    return run_query("SELECT * FROM android_intent_filters WHERE IsUnusual = %s", (1 if is_unusual else 0,))

def get_intent_filter_record_by_name(intent_name: str) -> Optional[Dict]:
    return next(iter(run_query("SELECT * FROM android_intent_filters WHERE IntentName = %s", (intent_name,))), None)

def get_all_services() -> List[Dict]:
    return run_query("SELECT * FROM android_services;")

def search_services_by_name(service_name: str) -> List[Dict]:
    like_term = f"%{service_name}%"
    return run_query("SELECT * FROM android_services WHERE ServiceName LIKE %s", (like_term,))

def get_malware_prone_services() -> List[Dict]:
    return run_query("SELECT * FROM android_services WHERE IsMalwareProne = 1")