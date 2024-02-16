# DBFunct_ApkRecords.py

from typing import Optional, Tuple, List, Dict
from . import DBConnectionManager as dbConnect
from utils import logging_utils, hash_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return dbConnect.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def get_apk_id_by_sha256(sha256_hash: str) -> Optional[int]:
    sql = "SELECT apk_id FROM apk_samples WHERE sha256 = %s"
    params = (sha256_hash,)
    result = run_query(sql, params)
    if result:
        return result[0][0]
    else:
        return None

def get_apk_samples() -> List[Dict]:
    return run_query("SELECT * FROM apk_samples ORDER BY apk_id")

def get_apk_sample_record_by_sha256(sha256) -> List[Dict]:
    return run_query(f"SELECT * FROM apk_samples where sha256 = '{sha256}' ORDER BY apk_id")

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
    query += " ORDER BY a.apk_id asc"
    return run_query(query, params)

def get_apk_record_sha256_by_id(apk_id: int) -> Optional[Tuple[int, str]]:
    return next(iter(run_query("SELECT apk_id, sha256 FROM apk_samples WHERE apk_id = %s", (apk_id,))), None)

def get_unanalyzed_malware_ioc_threats():
    query = """
    SELECT * FROM malware_ioc_threats x
    WHERE x.virustotal_url IS NULL AND x.no_virustotal_data IS NULL
    ORDER BY x.no_virustotal_data ASC
    """
    return run_query(query)

def update_malware_ioc_vt_url(id, url):
    query = "UPDATE malware_ioc_threats SET virustotal_url = %s WHERE id = %s"
    return run_query(query, (url, id))

def hash_query_alpha(hashes):
    """Query for each hash and collect matching and non-matching hashes."""
    matching_records = []
    non_matching_hashes = set(hashes)
    for hash_str in hashes:
        hash_type = hash_utils.determine_hash_type(hash_str)
        if hash_type:
            query = f"""
                SELECT a.apk_id, a.md5, a.sha256, a.source, b.name_1, b.name_2, b.virustotal_label, b.month, b.year
                FROM apk_samples a
                JOIN malware_ioc_threats b ON a.sha256 = b.sha256
                WHERE a.{hash_type} = %s
            """
            results = run_query(query, (hash_str,))
            if results:
                matching_records.extend(results)
                non_matching_hashes.remove(hash_str)
    return matching_records, non_matching_hashes