# database_utils_2.py

from utils import logging_utils
from typing import Dict, Optional

from . import db_manager as dbConnect

def get_total_records_to_process() -> int:
    try:
        sql = """
            SELECT COUNT(*) FROM android_malware_hashes
            WHERE id NOT IN (SELECT id FROM android_malware_hashes WHERE no_virustotal_match = 1)
            AND (md5 IS NULL OR sha1 IS NULL OR sha256 IS NULL);
        """
        result = dbConnect.execute_query(sql, fetch=True)
        return result[0][0] if result else 0
    except Exception as e:
        logging_utils.log_error("Error getting total records to process", e)
        return 0

def get_intent_filters(is_unusual: bool = True) -> list:
    try:
        sql = "SELECT * FROM android_intent_filters WHERE IsUnusual = %s"
        params = (1 if is_unusual else 0,)
        results = dbConnect.execute_query(sql, params, fetch=True)
        return results if results else []
    except Exception as e:
        logging_utils.log_error("Error fetching intent filters", e)
        return []

def get_intent_filter_record_by_name(intent_name: str) -> Optional[Dict]:
    try:
        sql = "SELECT * FROM android_intent_filters WHERE IntentName = %s"
        params = (intent_name,)
        result = dbConnect.execute_query(sql, params, fetch=True)
        return result[0] if result else None
    except Exception as e:
        logging_utils.log_error(f"Error fetching intent filter record for {intent_name}", e)
        return None