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
               m.malware_name AS Name,
               m.malware_family AS Family,
               m.virustotal_label,
               s.AhnLab_V3,
               s.Alibaba,
               s.Ikarus,
               s.Kaspersky,
               s.microsoft,
               s.Tencent,
               s.ZoneAlarm
        FROM malware_samples m
            JOIN vt_scan_analysis s
                ON s.apk_id = m.id
        WHERE m.sha256 = %s
        ORDER BY m.id
        limit 1
    """
    params = (sha256,)  # Parameters passed in a tuple

    try:
        results = db_conn.execute_query(sql, params=params, fetch=True)
        return results
    
    except Exception as e:
        print(f"Error fetching malware classification: {e}")
        return []
    
def check_hash_exists(md5: Optional[str] = None, sha1: Optional[str] = None, sha256: Optional[str] = None) -> bool:
    # Checks if a hash (MD5, SHA1, or SHA256) exists in the 'hash_data_ioc' table.
    # Returns True if the hash is found, False otherwise.
    sql = "SELECT id FROM hash_data_ioc WHERE "
    params = []
    conditions = []

    # Add conditions for each hash type
    if md5:
        conditions.append("md5 = %s")
        params.append(md5)
    if sha1:
        conditions.append("sha1 = %s")
        params.append(sha1)
    if sha256:
        conditions.append("sha256 = %s")
        params.append(sha256)

    # If no valid hash provided, return False
    if not conditions:
        print("[ERROR] No valid hash provided to check.")
        return False

    # Join the conditions with OR so it can match any of the hash types
    sql += " OR ".join(conditions)

    # Execute the query
    result = run_query(sql, tuple(params))
    if result:
        return True
    return False

# Function to get all records from the hash_data_ioc table
def get_all_hash_data() -> List[Dict]:
    try:
        sql = "SELECT * FROM hash_data_ioc"
        records = db_conn.execute_query(sql, fetch=True)
        if records:
            print(f"Retrieved {len(records)} record(s) from 'hash_data_ioc'.")
            return records
        else:
            print("No records found in 'hash_data_ioc'.")
            return None
    
    except Exception as e:
        print(f"[ERROR] Error retrieving records from 'hash_data_ioc': {e}")
        return []
    
from typing import List, Dict

def get_unanalyzed_database_hashes() -> List[Dict]:
    try:
        sql = """
            SELECT ms.sha256
            FROM malware_samples ms
            WHERE ms.data_type_description IS NULL
                OR ms.data_type_description = 'Android'
                OR ms.data_type_description NOT IN ('Win32 EXE', 'ZIP', 'Text', 'Shell script', 'RAR', 'JAR', 'ELF')
        """
        
        records = db_conn.execute_query(sql, fetch=True)
        if records:
            return [{"sha256": row[0]} for row in records]
        else:
            print("No unanalyzed SHA256 hashes found in 'hash_data_ioc'.")
            return []
    
    except Exception as e:
        print(f"[ERROR] Error retrieving unanalyzed SHA256 hashes: {e}")
        return []

