from datetime import datetime, timedelta
from typing import Optional, List, Dict
from . import db_conn

# Function to run a generic SQL query
def run_query(sql: str, params: Optional[tuple] = None) -> List[tuple]:
    try:
        return db_conn.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        print(f"Error executing SQL query: {sql}, Error: {e}")
        return []

# Function to run an insert/update query
def modify_query(sql: str, params: Optional[tuple] = None) -> bool:
    try:
        db_conn.execute_query(sql, params)
        return True
    except Exception as e:
        print(f"Error executing SQL update/insert: {sql}, Error: {e}")
        return False

# Reset the API key usage and last_reset timestamp for a specific API key
def reset_api_key(api_key_id: int) -> bool:
    sql = """
    UPDATE vt_api_keys
    SET current_requests = 0, last_reset = NOW()
    WHERE id = %s;
    """
    return modify_query(sql, (api_key_id,))

# Function to reset daily request counts for all API keys
def reset_api_key_usage() -> bool:
    sql = "UPDATE vt_api_keys SET current_requests = 0, last_reset = NOW();"
    return modify_query(sql)

# Check if the API key was last reset more than 24 hours ago
def check_and_reset_stale_keys():
    sql = """
    SELECT id, last_reset
    FROM vt_api_keys
    WHERE TIMESTAMPDIFF(HOUR, last_reset, NOW()) >= 24;
    """
    stale_keys = run_query(sql)

    if stale_keys:
        print("[INFO] Resetting stale API keys:")
        for key in stale_keys:
            print(f"Resetting key ID {key[0]} (last reset: {key[1]})")
            reset_api_key(key[0])

# Retrieve the least recently used API key that is within request limits
def get_available_api_key() -> Optional[Dict]:
    # Check if any keys need resetting before getting an available key
    check_and_reset_stale_keys()

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
    else:
        print("[ERROR] No available API keys found (all have reached their request limit).")
        return None
    
# Retrieve the least recently used API key that is within request limits
def get_virustotal_api_keys() -> Optional[Dict]:

    sql = "SELECT id, api_key FROM vt_api_keys"
    result = run_query(sql)
    if result:
        return result
    else:
        print("[ERROR] No available API keys found.")
        return None

# Insert a new API key into the database
def insert_vt_api_key(api_key: str, api_type: str = 'free', max_requests: int = 500) -> bool:
    sql = """
    INSERT INTO vt_api_keys (api_key, api_type, max_requests_per_day)
    VALUES (%s, %s, %s);
    """
    params = (api_key, api_type, max_requests)
    return modify_query(sql, params)

# Update API key usage after a request
def update_api_key_usage(key_id: int) -> bool:
    sql = """
    UPDATE vt_api_keys
    SET current_requests = current_requests + 1, last_used = NOW()
    WHERE id = %s;
    """
    return modify_query(sql, (key_id,))

# View all API keys with details
def view_all_api_keys() -> List[Dict]:
    sql = "SELECT * FROM vt_api_keys;"
    return run_query(sql)

# Delete an API key
def delete_api_key(key_id: int) -> bool:
    sql = "DELETE FROM vt_api_keys WHERE id = %s;"
    return modify_query(sql, (key_id,))
