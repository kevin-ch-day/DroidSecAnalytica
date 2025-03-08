# db_tableManagement.py

from typing import Optional, Dict, List
from utils import logging_utils
from . import db_conn as dbConnect

# Executes a SQL query and returns the results or None if should_fetch is False
def execute_sql(query: str, params: tuple = None, should_fetch: bool = False):
    try:
        return dbConnect.execute_query(query, params, fetch=should_fetch)
    except Exception as e:
        logging_utils.log_error(f"Error executing query: {query}", e)
        return None if should_fetch else False

# Checks if a specific table exists in the database
def check_for_table(table_name: str) -> bool:
    return bool(execute_sql("SHOW TABLES LIKE %s;", (table_name,), True))

# Lists all tables in the database with their column and row counts
def list_tables() -> list:
    result = execute_sql("SHOW TABLES;", should_fetch=True)
    if not result:
        return []

    table_info = []
    for (table_name,) in result:
        num_columns = len(execute_sql(f"SHOW COLUMNS FROM {table_name};", should_fetch=True))
        num_rows = execute_sql(f"SELECT COUNT(*) FROM {table_name};", should_fetch=True)[0][0]
        table_info.append((table_name, num_columns, num_rows))
    return table_info

# Creates a record for an APK sample
def create_apk_record(filename: str, filesize: int, md5: str, sha1: str, sha256: str):
    sql = "INSERT INTO malware_samples (filename, filesize, md5, sha1, sha256) VALUES (%s, %s, %s, %s, %s)"
    if execute_sql(sql, (filename, filesize, md5, sha1, sha256)):
        logging_utils.log_info("APK record created successfully.")

def truncate_analysis_data_tables() -> bool:
    print("\nClearing analysis tables...\n")

    table_names = [
        "analysis_metadata",
        "vt_activities",
        "vt_permissions",
        "vt_receivers",
        "vt_scan_analysis",
        "vt_services",
        "vt_providers"
        #"vt_certificates",
        #"vt_intent_filters_actions",
        #"vt_intent_filters_categories"
        ]
    
    try:
        for table_name in table_names:
            execute_sql(f"TRUNCATE TABLE {table_name}")
            print(f"Truncated: {table_name}")

        print("\nAnalysis tables were successfully truncated.")
        return True
    
    except Exception as e:
        logging_utils.log_error("An error occurred while truncating tables.", e)
        return False

# Updates a user's information based on the provided keyword arguments
def update_user(user_id: int, **kwargs) -> bool:
    try:
        update_values = ', '.join([f"{key} = %s" for key in kwargs.keys()])
        values = list(kwargs.values())
        values.append(user_id)
        sql = f"UPDATE droidsec_users SET {update_values} WHERE user_id = %s"
        dbConnect.execute_query(sql, tuple(values), fetch=False)
        return True
    except Exception as e:
        logging_utils.log_error(f"Error updating user with ID {user_id}", e)
        return False

# Deletes a user from the droidsec_users table
def delete_user(user_id: int) -> bool:
    try:
        sql = "DELETE FROM droidsec_users WHERE user_id = %s"
        dbConnect.execute_query(sql, (user_id,), fetch=False)
        return True
    except Exception as e:
        logging_utils.log_error(f"Error deleting user with ID {user_id}", e)
        return False

# Retrieves a user's information by their ID
def get_user_by_id(user_id: int) -> Optional[Dict]:
    try:
        sql = "SELECT * FROM droidsec_users WHERE user_id = %s"
        result = dbConnect.execute_query(sql, (user_id,), fetch=True)
        return result[0] if result else None
    except Exception as e:
        logging_utils.log_error(f"Error fetching user with ID {user_id}", e)
        return None

# Retrieves all users from the droidsec_users table
def get_all_users() -> List[Dict]:
    try:
        sql = "SELECT * FROM droidsec_users"
        return dbConnect.execute_query(sql, fetch=True)
    except Exception as e:
        logging_utils.log_error("Error fetching all users", e)
        return []

# Authenticates a user based on their username and password
def user_login(username: str, password: str) -> bool:
    try:
        user = get_user_by_username(username)
        if user and user['password'] == password:
            update_last_login(user['user_id'])
            return True
        return False
    except Exception as e:
        logging_utils.log_error("Error in user login", e)
        return False

# Retrieves a user's information by their username
def get_user_by_username(username: str) -> Optional[Dict]:
    try:
        sql = "SELECT * FROM droidsec_users WHERE username = %s"
        result = dbConnect.execute_query(sql, (username,), fetch=True)
        return result[0] if result else None
    except Exception as e:
        logging_utils.log_error(f"Error fetching user with username {username}", e)
        return None

# Updates the last login timestamp for a user
def update_last_login(user_id: int) -> bool:
    try:
        sql = "UPDATE droidsec_users SET last_login = CURRENT_TIMESTAMP WHERE user_id = %s"
        dbConnect.execute_query(sql, (user_id,), fetch=False)
        return True
    except Exception as e:
        logging_utils.log_error(f"Error updating last login for user ID {user_id}", e)
        return False

# Adds a new user to the droidsec_users table
def add_user(username: str, first_name: str, last_name: str, password: str, is_admin: bool = False) -> bool:
    try:
        sql = "INSERT INTO droidsec_users (username, first_name, last_name, password, is_admin) VALUES (%s, %s, %s, %s, %s)"
        dbConnect.execute_query(sql, (username, first_name, last_name, password, int(is_admin)), fetch=False)
        return True
    except Exception as e:
        logging_utils.log_error("Error adding new user", e)
        return False