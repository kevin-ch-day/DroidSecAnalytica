# Python Modules
from typing import Optional, List, Dict

# Custom Libraries
from . import db_conn
from utils import user_prompts, logging_utils

logger = logging_utils.get_logger(__name__)


def run_query(sql: str, params: Optional[tuple] = None, fetch: bool = False):
    """Execute an SQL statement with optional parameters.

    Returns query results when ``fetch`` is True and a boolean status otherwise.
    """
    try:
        result = db_conn.execute_query(sql, params, fetch=fetch)
        return result if fetch else True
    except Exception:
        logger.exception("SQL Execution Failed: %s | Params: %s", sql, params)
        return [] if fetch else False

# Reset API keys at UTC midnight
def reset_api_keys_at_utc_midnight():
    sql = """
    SELECT id
    FROM vt_api_keys 
    WHERE last_reset IS NULL OR TIMESTAMPDIFF(DAY, last_reset, UTC_TIMESTAMP()) >= 1;
    """
    
    stale_keys = run_query(sql, fetch=True)
    
    if stale_keys:
        logger.info("Resetting API keys at UTC midnight...")
        sql_reset = """
        UPDATE vt_api_keys
        SET current_requests = 0, last_reset = UTC_TIMESTAMP()
        WHERE id = %s;
        """

        for key in stale_keys:
            key_id = key[0]
            if run_query(sql_reset, (key_id,)):
                logger.info("API Key ID %s has been reset.", key_id)
    else:
        logger.info("No keys needed resetting at this time.")

# Reset API keys that have not been reset in the past 24 hours
def check_and_reset_api_keys():
    sql = """
    SELECT id, last_reset
    FROM vt_api_keys
    WHERE last_reset IS NULL OR TIMESTAMPDIFF(HOUR, last_reset, UTC_TIMESTAMP()) >= 24;
    """
    stale_keys = run_query(sql, fetch=True)

    if stale_keys:
        logger.info("Resetting API keys that have not been reset in the past 24 hours")
        reset_api_keys_at_utc_midnight()
    else:
        logger.info("All API keys are up-to-date")

# Update API key usage after a request
def update_api_key_usage(key_id: int) -> bool:
    sql = """
    UPDATE vt_api_keys
    SET current_requests = current_requests + 1, last_used = NOW()
    WHERE id = %s;
    """
    return run_query(sql, (key_id,))

# Retrieve the least recently used API key that is within request limits
def get_available_api_key() -> Optional[Dict]:
    # Check if any keys need resetting before getting an available key
    check_and_reset_api_keys()

    sql = """
    SELECT id, api_key, api_type, max_requests_per_day, current_requests, last_used
    FROM vt_api_keys
    WHERE current_requests < max_requests_per_day
    ORDER BY last_used ASC
    LIMIT 1;
    """
    result = run_query(sql)
    if result:
        return {
            "id": result[0][0],
            "api_key": result[0][1],
            "api_type": result[0][2],
            "max_requests_per_day": result[0][3],
            "current_requests": result[0][4],
            "last_used": result[0][5]
        }
    logger.error("No available API keys found (all have reached their request limit)")
    return None

# Retrieve all API keys
def get_virustotal_api_keys() -> List[Dict]:
    sql = "SELECT id, api_key FROM vt_api_keys"
    result = run_query(sql, fetch=True)

    return [{"id": row[0], "api_key": row[1]} for row in result]

# Displays all VirusTotal API keys
def view_api_keys():
    api_keys = get_virustotal_api_keys()

    if api_keys:
        print("\n===================================")
        print("          *** API KEYS ***          ")
        print("===================================")

        for key in api_keys:
            print(f"ID: {key['id']} | API Key: {key['api_key'][:10]}...")

        print("\n===================================")
    else:
        print("[INFO] No API keys available.")

# Prompts user to input and add a new VirusTotal API key
def add_api_key():
    api_key = input("Enter the new VirusTotal API Key: ").strip()
    api_type = user_prompts.user_menu_choice("Select API Type (free or premium): ", ['free', 'premium'])

    sql = """
    INSERT INTO vt_api_keys (api_key, api_type, max_requests_per_day)
    VALUES (%s, %s, 500);
    """
    
    if run_query(sql, (api_key, api_type)):
        logger.info("API key added successfully")
        print("The key was successfully added.")
    else:
        logger.error("Failed to add the new API key")
        print("Failed to add the new API key.")

# Prompts user to delete an API key
def delete_api_key_prompt():
    view_api_keys()
    api_key_id = input("Enter the API Key ID to delete: ").strip()

    sql = "DELETE FROM vt_api_keys WHERE id = %s;"
    
    if run_query(sql, (api_key_id,)):
        logger.info("API key %s deleted", api_key_id)
        print(f"API key {api_key_id} deleted successfully.")
    else:
        logger.error("Failed to delete API key %s", api_key_id)
        print(f"Failed to delete API key {api_key_id}.")
