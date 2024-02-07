from typing import Optional, List, Dict
from . import DBConnectionManager as dbConnect

def run_query(sql: str, params: Optional[tuple] = None, is_select: bool = True) -> List[tuple]:
    try:
        conn = dbConnect.get_database_connection()
        cursor = conn.cursor()
        cursor.execute(sql, params)
        if is_select:
            result = cursor.fetchall()
            cursor.close()
            return result
        conn.commit()
        cursor.close()
        return []
    except Exception as e:
        print(f"Error executing SQL query: {sql}", e)
        if 'cursor' in locals():
            cursor.close()
        return []

def get_permission_id_by_name(perm_name: str) -> Optional[int]:
    result = run_query("SELECT permission_id FROM android_permissions WHERE constant_value = %s", (perm_name,))
    return result[0][0] if result else None

def get_permission_record_by_name(perm_name: str) -> Optional[Dict]:
    result = run_query("SELECT * FROM android_permissions WHERE constant_value = %s", (perm_name,))
    if result:
        return result[0]
    return None

def get_unknown_permission_id(perm_name: str) -> Optional[int]:
    result = run_query("SELECT permission_id FROM android_permissions_unknown WHERE constant_value = %s", (perm_name,))
    return result[0][0] if result else None

def get_unknown_permission_record_by_id(perm_name: str) -> Optional[int]:
    result = run_query("SELECT * FROM android_permissions_unknown WHERE constant_value = %s", (perm_name,))
    if result:
        return result[0]
    return None

def is_unknown_perm_table_empty() -> bool:
    result = run_query("SELECT COUNT(*) FROM android_permissions_unknown")
    return not result[0][0]

def get_all_permissions() -> List[Dict]:
    result = run_query("SELECT * FROM android_permissions;")
    columns = ["permission_id", "constant_value", "andro_short_desc", "andro_long_desc", "andro_type"]
    return [dict(zip(columns, row)) for row in result]

def get_permissions_by_category(category: str) -> List[Dict]:
    result = run_query("SELECT * FROM android_permissions WHERE category = %s", (category,))
    columns = ["permission_id", "constant_value", "andro_short_desc", "andro_long_desc", "andro_type"]
    return [dict(zip(columns, row)) for row in result]

def search_permission(search_term: str) -> List[Dict]:
    like_term = f"%{search_term}%"
    result = run_query("SELECT * FROM android_permissions WHERE permission_name LIKE %s OR description LIKE %s", (like_term, like_term))
    columns = ["permission_id", "constant_value", "andro_short_desc", "andro_long_desc", "andro_type"]
    return [dict(zip(columns, row)) for row in result]

def reorder_unknown_permissions():
    offset = 90000
    run_query("UPDATE android_permissions_unknown SET permission_id = permission_id + %s", (offset,), is_select=False)
    permissions = run_query("SELECT permission_id FROM android_permissions_unknown ORDER BY constant_value ASC")
    for new_id, (temp_permission_id,) in enumerate(permissions, start=1):
        run_query("UPDATE android_permissions_unknown SET permission_id = %s WHERE permission_id = %s", (new_id, temp_permission_id + offset), is_select=False)
    print("Unknown permissions reordered successfully.")

def check_unknown_permission_record(permission_id: int, permission_name: str, short_desc: str, long_desc: str, permission_type: str):
    print("Executing check_unknown_permission_record function...")
    field_mapping = {
        "constant_value": ("constant_value", None, permission_name),
        "andro_short_desc": ("andro_short_desc", None, short_desc),
        "andro_long_desc": ("andro_long_desc", None, long_desc),
        "andro_type": ("andro_type", None, permission_type),
    }
    check_permission_record_update(permission_id, field_mapping, "android_permissions_unknown")

def check_standard_permission_record(permission_id: int, permission_name: str, short_desc: str, long_desc: str, permission_type: str):
    print("Executing check_standard_permission_record function...")
    field_mapping = {
        "constant_value": ("constant_value", None, permission_name),
        "andro_short_desc": ("andro_short_desc", None, short_desc),
        "andro_long_desc": ("andro_long_desc", None, long_desc),
        "andro_type": ("andro_type", None, permission_type),
    }
    check_permission_record_update(permission_id, field_mapping, "android_permissions")

def check_permission_record_update(permission_id, field_mapping, table_name):
    try:
        query = f"""
        SELECT permission_id, constant_value, andro_short_desc, andro_long_desc, andro_type
        FROM {table_name} WHERE permission_id = %s
        """
        result = run_query(query, (permission_id,))
        if not result:
            print("\nNo permission record found.\n")
            return

        updates = []
        for field, (column_name, db_value, provided_value) in field_mapping.items():
            if provided_value is not None and db_value is None:
                print(f"\nUpdating {field}: Database = None, Provided = '{provided_value}'")
                update_required = input(f"Update {field} to provided value? [y/N]: ").strip().lower() == 'y'
                if update_required:
                    updates.append((column_name, provided_value))

        if updates:
            with dbConnect.database_connection() as conn:
                cursor = conn.cursor()
                try:
                    for column_name, value in updates:
                        update_query = f"UPDATE {table_name} SET {column_name} = %s WHERE permission_id = %s"
                        cursor.execute(update_query, (value, permission_id))
                    conn.commit()
                    print("\nUpdates applied successfully.\n")
                except Exception as e:
                    print(f"\nFailed to apply updates: {e}\n")
                    conn.rollback()
                finally:
                    cursor.close()

    except Exception as e:
        print("Error running the analysis:", e)
