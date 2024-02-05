# DBFunct_Perm.py

from typing import Optional, Tuple, List, Dict
from . import DBConnectionManager as dbConnect
from utils import logging_utils

def run_query(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    try:
        return dbConnect.execute_query(sql, params, fetch=True) or []
    except Exception as e:
        logging_utils.log_error(f"Error executing SQL query: {sql}", e)
        return []

def get_permission_id_by_name(perm_name: str) -> Optional[int]:
    result = run_query("SELECT permission_id FROM android_permissions WHERE constant_value = %s", (perm_name,))
    return result[0]['permission_id'] if result else None

def get_unknown_permission_id(perm_name: str) -> Optional[int]:
    result = run_query("SELECT permission_id FROM unknown_permissions WHERE constant_value = %s", (perm_name,))
    return result[0]['permission_id'] if result else None

def is_unknown_perm_table_empty() -> bool:
    result = run_query("SELECT COUNT(*) as count FROM unknown_permissions")
    return result[0]['count'] == 0

def get_all_permissions() -> List[Dict]:
    return run_query("SELECT * FROM android_permissions;")

def get_permissions_by_category(category: str) -> List[Dict]:
    return run_query("SELECT * FROM android_permissions WHERE category = %s", (category,))

def search_permission(search_term: str) -> List[Dict]:
    like_term = f"%{search_term}%"
    return run_query("SELECT * FROM android_permissions WHERE permission_name LIKE %s OR description LIKE %s", (like_term, like_term))

def reorder_unknown_permissions():
    with dbConnect.database_connection() as conn:
        try:
            cursor = conn.cursor()
            # Step 1: Temporarily increase permission_id by an offset to avoid PRIMARY key conflict
            offset = 90000  # Use an offset larger than the current max permission_id in the table
            cursor.execute("UPDATE unknown_permissions SET permission_id = permission_id + %s", (offset,))

            # Step 2: Fetch all permissions with the temporary offset, ordered by your criteria (e.g., constant_value)
            cursor.execute("SELECT permission_id FROM unknown_permissions ORDER BY constant_value ASC")
            permissions = cursor.fetchall()

            # Step 3: Reset permission_id to sequential order starting from 1
            new_id = 1
            for (temp_permission_id,) in permissions:
                cursor.execute("UPDATE unknown_permissions SET permission_id = %s WHERE permission_id = %s", (new_id, temp_permission_id + offset))
                new_id += 1

            conn.commit()  # Commit the transaction after all updates
            logging_utils.log_info("Unknown permissions reordered successfully.")
        except Exception as e:
            conn.rollback()  # Rollback in case of any error
            logging_utils.log_error("Failed to reorder unknown permissions", e)
