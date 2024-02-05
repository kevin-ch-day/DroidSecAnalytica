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

def get_apk_samples() -> List[Dict]:
    return run_query("SELECT * FROM apk_samples ORDER BY apk_id")

def get_apk_samples_sha256() -> List[Dict]:
    return run_query("SELECT apk_id, sha256 FROM apk_samples ORDER BY apk_id")

def get_malware_hash_samples() -> List[Dict]:
    return run_query("SELECT * FROM malware_ioc_threats")

def update_apk_record(record_id: int, data: Dict) -> None:
    updates = ", ".join([f"{k} = %s" for k in data.keys()])
    values = list(data.values()) + [record_id]
    query = f"UPDATE apk_samples SET {updates} WHERE apk_id = %s"
    dbConnect.execute_query(query, tuple(values), fetch=False)

def get_apk_records_sha256(apk_id: Optional[int] = None) -> Optional[List[Tuple[int, str]]]:
    query = """
    SELECT a.apk_id, a.sha256 FROM apk_samples a
    JOIN malware_ioc_threats b ON a.sha256 = b.sha256
    WHERE b.no_virustotal_data IS NULL
    """
    params = ()
    if apk_id:
        query += " AND a.apk_id >= %s"
        params = (apk_id,)
    query += " ORDER BY a.apk_id ASC"
    return run_query(query, params)

def get_apk_record_sha256_by_id(apk_id: int) -> Optional[Tuple[int, str]]:
    return next(iter(run_query("""
    SELECT apk_id, sha256 FROM apk_samples
    WHERE apk_id = %s
    """, (apk_id,))), None)

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