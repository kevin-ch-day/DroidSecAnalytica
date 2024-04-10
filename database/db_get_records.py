# db_get_records.py

from typing import Optional, Tuple, List, Dict
from . import db_conn
from utils import logging_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return db_conn.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def get_apk_samples() -> List[Dict]:
    return run_query("SELECT * FROM apk_samples ORDER BY apk_id")

def get_malware_hash_samples() -> List[Dict]:
    return run_query("SELECT * FROM malware_ioc_threats")

def get_apk_id_by_sha256(sha256: str) -> Optional[int]:
    sql = "SELECT id FROM malware_samples WHERE sha256 = %s"
    params = (sha256,)
    result = run_query(sql, params)
    if result:
        return result[0][0]
    else:
        return None

def get_apk_sample_record_by_sha256(sha256) -> List[Dict]:
    return run_query(f"SELECT * FROM apk_samples where sha256 = '{sha256}' ORDER BY apk_id")

def get_samples_id_sha256() -> List[Dict]:
    return run_query("SELECT apk_id, sha256 FROM apk_samples ORDER BY apk_id")

def get_apk_sha256_by_id(apk_id: int) -> Optional[Tuple[int, str]]:
    return next(iter(run_query("SELECT apk_id, sha256 FROM apk_samples WHERE apk_id = %s", (apk_id,))), None)

def get_apk_samples_by_sha256(sha256_list: List[str]) -> List[Dict]:
    # Queries the apk_samples table for records matching a list of SHA256 hashes.
    matching_records = []
    for sha256 in sha256_list:
        records = run_query("SELECT * FROM apk_samples WHERE sha256 = %s", (sha256,))
        if records:
            matching_records.extend(records)
    return matching_records

def get_apk_samples_by_md5(md5_hashes: List[str]) -> List[Dict]:
    # Queries the apk_samples table for records matching a list of MD5 hashes.
    placeholders = ', '.join(['%s'] * len(md5_hashes))
    query = f"SELECT * FROM malware_samples WHERE md5 IN ({placeholders}) order by vt_first_submission ASC"
    records = run_query(query, md5_hashes)
    return records

def get_all_sample_md5_to_analyze() -> List[Dict]:
    sql = """
    select DISTINCT ms.md5
    from malware_samples ms
    left join analysis_metadata am
        on ms.sha256 = am.sha256
    order by ms.id
    """
    return run_query(sql)

def get_vt_scan_analysis_columns():
    query = "SHOW COLUMNS FROM vt_scan_analysis"
    column_names = []
    with db_conn.database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        column_names = [column[0] for column in cursor.fetchall()]
    return column_names

def get_malware_classification(sha256):
    # Retrieves malware classification information for a given SHA-256 hash.
    sql = """
        SELECT m.id,
               m.name_1 AS Name,
               m.name_2 AS Family,
               m.virustotal_label,
               s.AhnLab_V3,
               s.Alibaba,
               s.Ikarus,
               s.Kaspersky,
               s.microsoft,
               s.Tencent,
               s.ZoneAlarm
        FROM malware_samples m
        JOIN vt_scan_analysis s ON s.apk_id = m.id
        WHERE m.sha256 = %s
        ORDER BY m.id
    """
    params = (sha256,)  # Parameters passed in a tuple

    try:
        results = db_conn.execute_query(sql, params=params, fetch=True)
        return results
    
    except Exception as e:
        print(f"Error fetching malware classification: {e}")
        return []