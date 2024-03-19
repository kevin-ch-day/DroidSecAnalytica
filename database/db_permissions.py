# db_permissions.py

from typing import Optional, List, Dict
from . import db_conn as dbConnect

def run_query(sql: str, params: Optional[tuple] = None, is_select: bool = True) -> List[tuple]:
    try:
        conn = dbConnect.get_database_connection()
        cursor = conn.cursor()
        cursor.execute(sql, params)
        if is_select:
            result = cursor.fetchall()
        else:
            conn.commit()
            result = []

        cursor.close()
        return result
    except Exception as e:
        print(f"Error executing SQL query: {sql}", e)
        if 'cursor' in locals():
            cursor.close()
        return []

def get_permission_record_by_id(perm_id: int) -> Optional[Dict]:
    result = run_query("SELECT * FROM android_permissions WHERE permission_id = %s", (perm_id,))
    return result[0] if result else None

def get_permission_record_by_name(perm_name: str) -> Optional[Dict]:
    result = run_query("SELECT * FROM android_permissions WHERE constant_value = %s", (perm_name,))
    return result[0] if result else None

def get_unknown_permission_record_by_id(perm_id: int) -> Optional[Dict]:
    result = run_query("SELECT * FROM android_permissions_unknown WHERE permission_id = %s", (perm_id,))
    return result[0] if result else None

def get_unknown_permission_record_by_name(perm_name: str) -> Optional[Dict]:
    result = run_query("SELECT * FROM android_permissions_unknown WHERE constant_value = %s", (perm_name,))
    return result[0] if result else None

def is_unknown_perm_table_empty() -> bool:
    result = run_query("SELECT COUNT(*) FROM android_permissions_unknown")
    return result[0][0] == 0

def get_permissions(table_name: str, columns: List[str]) -> List[Dict]:
    result = run_query(f"SELECT * FROM {table_name};")
    return [dict(zip(columns, row)) for row in result]

def get_permissions_by_category(category: str) -> List[Dict]:
    columns = ["permission_id", "constant_value", "andro_short_desc", "andro_long_desc", "andro_type"]
    return get_permissions("android_permissions", columns)

def search_permission(search_term: str) -> List[Dict]:
    like_term = f"%{search_term}%"
    columns = ["permission_id", "constant_value", "andro_short_desc", "andro_long_desc", "andro_type"]
    return get_permissions("android_permissions", columns)

def reorder_unknown_permissions():
    offset = 90000
    run_query("UPDATE android_permissions_unknown SET permission_id = permission_id + %s", (offset,), is_select=False)
    permissions = run_query("SELECT permission_id FROM android_permissions_unknown ORDER BY constant_value ASC")
    for new_id, (temp_permission_id,) in enumerate(permissions, start=1):
        run_query("UPDATE android_permissions_unknown SET permission_id = %s WHERE permission_id = %s", (new_id, temp_permission_id + offset), is_select=False)
    print("Unknown permissions reordered successfully.")

def check_permission_record(id, short_desc, long_desc, perm_type, table_name):
    try:
        result = retrieve_permission_record(id, table_name)
        if not result:
            print(f"No permission record found for ID {id}.")
            return

        db_short_desc, db_long_desc, db_perm_type = result
        if db_short_desc is None:
            update_permission_field(id, table_name, "andro_short_desc", short_desc, db_short_desc)
        elif db_short_desc != short_desc:
            update_permission_field(id, table_name, "andro_short_desc", short_desc, db_short_desc)

        if db_long_desc is None:
            update_permission_field(id, table_name, "andro_long_desc", long_desc, db_long_desc)
        elif db_long_desc != long_desc:
            update_permission_field(id, table_name, "andro_long_desc", long_desc, db_long_desc)

        if db_perm_type is None:
            update_permission_field(id, table_name, "andro_type", perm_type, db_perm_type)
        elif db_perm_type != perm_type:
            update_permission_field(id, table_name, "andro_type", perm_type, db_perm_type)

    except Exception as e:
        print(f"An error occurred while checking the permission record: {e}")

def retrieve_permission_record(id, table_name):
    result = run_query(f"SELECT andro_short_desc, andro_long_desc, andro_type FROM {table_name} WHERE permission_id = %s", (id,))
    return result[0] if result else None

def check_standard_permission_record(id, short_desc, long_desc, perm_type):
    check_permission_record(id, short_desc, long_desc, perm_type, "android_permissions")

def check_unknown_permission_record(id, short_desc, long_desc, perm_type):
    check_permission_record(id, short_desc, long_desc, perm_type, "android_permissions_unknown")

def update_permission_field(id, table_name, field_name, new_value, db_value, run_query_flag=False):
    try:
        if db_value is None:
            if field_name == 'andro_type' and new_value == 'Signatureorsystemordevelopment':
                new_value = 'Signature|System|Development'
            elif field_name == 'andro_type' and new_value == 'Signatureorsystem':
                new_value = 'Signature|System'

            print(f"No current value found for {field_name}. Automatically updating...")
            sql = f"UPDATE {table_name} SET {field_name} = %s WHERE permission_id = %s"
            run_query(sql, (new_value, id), False)
            return
        
        if run_query_flag:
            print(f"Current {field_name}: {db_value}")
            if db_value == new_value:
                print(f"No update needed for {field_name}.")
                return

            if field_name == 'andro_type' and new_value == 'Signatureorsystemordevelopment':
                new_value = 'Signature|System|Development'
            elif field_name == 'andro_type' and new_value == 'Signatureorsystem':
                new_value = 'Signature|System'

            # Format the field name with backticks if it contains spaces
            formatted_field_name = f"`{field_name}`" if ' ' in field_name else field_name
            print(f"Table Column: {field_name}")
            print(f"Current Value: {db_value}")
            print(f"\nNew: '{new_value}'")

            # Prompt the user for confirmation if db_value is not None
            update_required = input("\nDo you want to update this field? [y/N]: ").strip().lower() == 'y'
            if update_required:        
                update_query = f"UPDATE {table_name} SET {formatted_field_name} = %s WHERE permission_id = %s"
                run_query(update_query, (new_value, id), False)
                print(f"{field_name} updated successfully.")

    except Exception as e:
        print(f"Error updating {field_name}: {e}")

def get_next_permission_id(table_name: str) -> int:
    try:
        result = run_query(f"SELECT MAX(permission_id) FROM {table_name}")
        max_id = result[0][0]
        return max_id + 1 if max_id is not None else 1

    except Exception as e:
        print(f"Error getting next permission ID: {e}")
        return -1

def insert_unknown_permission_record(constant_value: str, short_desc: str, long_desc: str, permission_type: str):
    try:
        next_id = get_next_permission_id("android_permissions_unknown")
        if next_id == -1:
            print("Failed to determine next permission ID. Insertion aborted.")
            return
        
        query = "INSERT INTO android_permissions_unknown (permission_id, constant_value, andro_short_desc, andro_long_desc, andro_type) VALUES (%s, %s, %s, %s, %s)"
        run_query(query, (next_id, constant_value, short_desc, long_desc, permission_type), False)
        print(f"{constant_value} inserted successfully.")

        return get_unknown_permission_record_by_name(constant_value)

    except Exception as e:
        print(f"Error inserting new record: {e}")

def insert_standard_permission_record(constant_value: str, short_desc: str, long_desc: str, permission_type: str):
    try:
        next_id = get_next_permission_id("android_permissions")
        if next_id == -1:
            print("Failed to determine next permission ID. Insertion aborted.")
            return
        
        insert_query = "INSERT INTO android_permissions (permission_id, permission_name, constant_value, andro_short_desc, andro_long_desc, andro_type) VALUES (%s, %s, %s, %s, %s, %s)"
        run_query(insert_query, (next_id, constant_value, constant_value, short_desc, long_desc, permission_type), False)
        print(f"{constant_value} inserted successfully.")

    except Exception as e:
        print(f"Error inserting new record: {e}")
