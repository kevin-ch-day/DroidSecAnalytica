# db_get_records.py

from typing import Optional, List, Dict
from . import db_conn
from utils import logging_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    """Executes a query and returns results as a list of dictionaries."""
    try:
        results = db_conn.execute_query(sql, params, fetch=True)
        if results:
            column_names = [desc[0] for desc in db_conn.execute_query("SHOW COLUMNS FROM malware_samples", fetch=True)]
            return [dict(zip(column_names, row)) for row in results]
        return []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def get_apk_id_by_sha256(sha256: str) -> Optional[int]:
    """Fetches the APK ID for a given SHA-256 hash."""
    sql = "SELECT id FROM malware_samples WHERE sha256 = %s"
    result = run_query(sql, (sha256,))
    return result[0]['id'] if result else None

def get_apk_samples_by_md5(md5_hashes: List[str], batch_size: int = 100) -> List[Dict]:
    """Fetches APK samples by MD5 hashes with batch processing."""
    results = []
    for i in range(0, len(md5_hashes), batch_size):
        batch = md5_hashes[i : i + batch_size]
        placeholders = ', '.join(['%s'] * len(batch))
        query = f"SELECT * FROM malware_samples WHERE md5 IN ({placeholders}) ORDER BY vt_first_submission ASC"
        results.extend(run_query(query, tuple(batch)))
    return results

def get_all_sample_md5_to_analyze() -> List[Dict]:
    """Fetches all MD5 hashes that have not been analyzed yet."""
    sql = """
    SELECT DISTINCT ms.md5
    FROM malware_samples ms
    LEFT JOIN analysis_metadata am
        ON ms.sha256 = am.sha256
    ORDER BY ms.id
    """
    return run_query(sql)

def check_hash_exists(md5: Optional[str] = None, sha1: Optional[str] = None, sha256: Optional[str] = None) -> bool:
    """Checks if an MD5, SHA1, or SHA256 hash exists in hash_data_ioc."""
    conditions, params = [], []
    
    if md5:
        conditions.append("md5 = %s")
        params.append(md5)
    if sha1:
        conditions.append("sha1 = %s")
        params.append(sha1)
    if sha256:
        conditions.append("sha256 = %s")
        params.append(sha256)

    if not conditions:
        logging_utils.log_error("No valid hash provided to check.")
        return False

    sql = f"SELECT id FROM hash_data_ioc WHERE {' OR '.join(conditions)}"
    return bool(run_query(sql, tuple(params)))

def get_all_hash_data() -> List[Dict]:
    """Fetches all records from hash_data_ioc."""
    sql = "SELECT * FROM hash_data_ioc"
    return run_query(sql)

def get_unanalyzed_database_hashes() -> List[str]:
    """Retrieves a list of SHA-256 hashes from malware_samples that have not been analyzed."""
    sql = """
        SELECT ms.sha256, ms.no_virustotal_data
        FROM malware_samples ms
        WHERE ms.no_virustotal_data is null
        AND NOT EXISTS (
            SELECT 1 FROM analysis_metadata am WHERE am.sha256 = ms.sha256
        )
        AND (
            ms.data_type_description IS NULL 
            OR TRIM(ms.data_type_description) = 'Android'
            OR TRIM(ms.data_type_description) NOT IN (
                'Win32 EXE',
                'Shell script',
                'Text',
                'RAR',
                'ELF',
                'JAR',
                'ZIP',
                'Win32 DLL',
                'Rich Text Format'
            )
        );
    """
    results = run_query(sql)
    return [row['id'] for row in results] if results else []
