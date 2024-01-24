# database_utils_2.py

from utils import logging_utils
from typing import Dict, Optional

from . import DBConnectionManager as dbConnect

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