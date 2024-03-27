# db_func.py

from . import db_conn_v2 as db_conn

def execute_sql_query(sql_query):
    # Execute the given SQL query and handle exceptions
    try:
        return db_conn.execute_query(sql_query, fetch=True)
    except Exception as e:
        print(f"SQL query execution error: {e}")
        return []

def fetch_vendor_data():
    sql_query = "SELECT * FROM vendor_details order by vendor"
    results = execute_sql_query(sql_query)
    if not results:
        print("No data fetched or an error occurred.")
    return results

def fetch_vendor_unknown_permission_prefixes():
    # Fetch vendor unknown permission prefixes from the database
    sql_query = """
        SELECT CONCAT(
            SUBSTRING_INDEX(SUBSTRING_INDEX(constant_value, '.', 1), '.', -1), 
            '.', 
            SUBSTRING_INDEX(SUBSTRING_INDEX(constant_value, '.', 2), '.', -1)
        ) AS prefix,
        COUNT(*) AS count
    FROM android_permissions_unknown
    WHERE constant_value LIKE 'com.%' OR constant_value LIKE 'org.%'
    GROUP BY prefix
    """
    results = execute_sql_query(sql_query)
    if not results:
        print("No data fetched or an error occurred.")
    return results

def fetch_all_unknown_permission_prefixes():
    # Fetch all unknown permission prefixes from the database
    sql_query = """
        SELECT CONCAT(
            SUBSTRING_INDEX(SUBSTRING_INDEX(constant_value, '.', 1), '.', -1), 
            '.', 
            SUBSTRING_INDEX(SUBSTRING_INDEX(constant_value, '.', 2), '.', -1)
        ) AS prefix,
        COUNT(*) AS count
    FROM android_permissions_unknown
    GROUP BY prefix
    """
    results = execute_sql_query(sql_query)
    if not results:
        print("No data fetched or an error occurred.")
    return results

def fetch_vendor_manufacturer_permission_prefixes():
    # Fetch vendor manufacturer permission prefixes from the database
    sql_query = """
        SELECT CONCAT(
            SUBSTRING_INDEX(SUBSTRING_INDEX(constant_value, '.', 1), '.', -1), 
            '.', 
            SUBSTRING_INDEX(SUBSTRING_INDEX(constant_value, '.', 2), '.', -1)
        ) AS prefix,
        COUNT(*) AS count
    FROM android_manufacturer_permissions
    WHERE constant_value LIKE 'com.%' OR constant_value LIKE 'org.%'
    GROUP BY prefix
    """
    results = execute_sql_query(sql_query)
    if not results:
        print("No data fetched or an error occurred.")
    return results

def fetch_manufacturer_permissions():
    # Fetch manufacturer permissions from the database
    sql_query = "SELECT * FROM android_manufacturer_permissions ORDER BY constant_value"
    results = execute_sql_query(sql_query)
    if not results:
        print("No suspicious permissions found.")
    return results

def fetch_unknown_permissions():
    # Fetch unknown permissions from the database
    sql_query = "SELECT * FROM android_permissions_unknown ORDER BY constant_value"
    results = execute_sql_query(sql_query)
    if not results:
        print("No unknown permissions found.")
    return results

def fetch_detailed_unknown_permissions_by_prefix(prefix):
    # Fetch detailed information for unknown permissions by their prefix.
    sql_query = f"SELECT * FROM android_permissions_unknown WHERE constant_value LIKE '{prefix}%'"
    return execute_sql_query(sql_query)

def insert_permission_into_manufacturer_table(permission_record):
    """
    Inserts a permission record into the android_manufacturer_permissions table.
    """
    sql = "INSERT INTO android_manufacturer_permissions (constant_value) VALUES (%s)"
    try:
        if db_conn.execute_query(sql, fetch=False, params=(permission_record['constant_value'],)):
            print(f"Permission {permission_record['constant_value']} inserted into manufacturer permissions table.")
            return True
    except Exception as e:
        print(f"Error inserting permission into manufacturer table: {e}")
    return False

def remove_permission_from_unknown_table(permission_id):
    """
    Removes a permission record from the android_permissions_unknown table by its ID.
    """
    sql = "DELETE FROM android_permissions_unknown WHERE permission_id = %s"
    try:
        if db_conn.execute_query(sql, fetch=False, params=(permission_id,)):
            print(f"Permission with ID {permission_id} removed from unknown permissions table.")
            return True
    except Exception as e:
        print(f"Error removing permission from unknown table: {e}")
    return False

def find_duplicate_constant_values():
    query = """
    SELECT constant_value, COUNT(*) as cnt
    FROM android_manufacturer_permissions
    GROUP BY constant_value
    HAVING COUNT(*) > 1;
    """
    return db_conn.execute_query(query, fetch=True)

def get_id_to_keep_for_duplicate(constant_value):
    query = """
    SELECT permission_id
    FROM android_manufacturer_permissions
    WHERE constant_value = %s
    ORDER BY last_updated ASC
    LIMIT 1;
    """
    result = db_conn.execute_query(query, (constant_value,), fetch=True)
    return result[0]['permission_id'] if result else None

def delete_duplicate_rows(constant_value, id_to_keep):
    query = """
    DELETE FROM android_manufacturer_permissions
    WHERE constant_value = %s AND permission_id != %s;
    """
    cursor = db_conn.execute_query(query, (constant_value, id_to_keep), fetch=False)
    return cursor.rowcount

def check_constant_value_exists(value):
    query = """
    SELECT COUNT(*) AS cnt
    FROM android_manufacturer_permissions
    WHERE constant_value = %s;
    """
    result = db_conn.execute_query(query, (value,), fetch=True)
    return result[0]['cnt'] > 0

def fetch_android_manufacturer_permission_id_by_value(constant_value):
    query = "SELECT permission_id FROM android_manufacturer_permissions WHERE constant_value = %s"
    result = db_conn.execute_query(query, (constant_value,), fetch=True)
    return result[0]['permission_id'] if result else None