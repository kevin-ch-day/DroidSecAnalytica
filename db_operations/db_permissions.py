# db_permissions.py

from typing import Optional, List, Dict, Tuple
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

# Fetch permissions for a list of APKs identified by their MD5 hashes. If no list is provided, fetch all permissions.
def fetch_apk_permissions(md5_list: List[str]) -> List[Tuple]:
    # Base SQL query without the WHERE clause
    sql = """
        SELECT a.id AS 'APK ID',
               e.permission_name AS 'Perm Name',
               e.protection_level AS 'Protection Level'
        FROM malware_samples a
            JOIN analysis_metadata c
                ON c.sha256 = a.sha256
            JOIN vt_permissions d
                ON d.analysis_id = c.analysis_id
                AND d.apk_id = a.id
            JOIN android_permissions e
                ON e.permission_id = d.known_permission_id
    """
    
    # Add WHERE clause only if md5_list is provided
    if md5_list:
        md5_placeholders = ', '.join(['%s'] * len(md5_list))
        sql += f" WHERE a.md5 IN ({md5_placeholders})"

    # Append the ORDER BY clause
    sql += " ORDER BY a.id, e.protection_level"
    
    # Execute the query
    return run_query(sql, tuple(md5_list) if md5_list else (), is_select=True)

# Retrieve detailed info on known permissions including name, constant value, protection level, and type
def get_known_permissions() -> List[Tuple]:
    sql = """
        SELECT DISTINCT x.known_permission_id,
                        y.permission_name,
                        y.constant_value,
                        y.description,
                        y.added_in_api,
                        y.deprecated_in_api
                        y.protection_level,
                        y.no_third_party_apps
                        y.andro_type
        FROM vt_permissions x
        JOIN android_permissions y
            ON y.permission_id = x.known_permission_id
        WHERE x.known_permission_id IS NOT NULL
        ORDER BY x.known_permission_id;
    """
    return run_query(sql, is_select=True)

# Fetch details on unknown permissions that might indicate new or undocumented permissions used by APKs
def get_unknown_permissions() -> List[Tuple]:
    sql = """
        SELECT DISTINCT x.unknown_permission_id,
                        y.constant_value,
                        y.andro_short_desc,
                        y.andro_type
        FROM vt_permissions x
        JOIN android_permissions_unknown y
            ON y.permission_id = x.unknown_permission_id
        WHERE x.unknown_permission_id IS NOT NULL
        ORDER BY y.constant_value;
    """
    return run_query(sql, is_select=True)

# Analyze APKs to identify those with a high number of dangerous permissions as defined by protection level or type
def get_apk_risk_profile() -> List[Tuple]:
    sql = """
        SELECT a.package_name, a.main_activity, a.target_sdk_version, COUNT(p.known_permission_id) AS num_high_risk_permissions
        FROM apk_analysis a
        INNER JOIN vt_permissions p ON a.analysis_id = p.analysis_id
        INNER JOIN android_permissions ap ON p.known_permission_id = ap.permission_id
        WHERE ap.protection_level LIKE '%dangerous%' OR ap.andro_type LIKE '%Dangerous%'
        GROUP BY a.package_name
        HAVING num_high_risk_permissions > 0
        ORDER BY num_high_risk_permissions DESC;
    """
    return run_query(sql, is_select=True)

# Retrieve permissions that are deprecated as of the APK's target SDK version, indicating potential security risks
def get_deprecated_permissions() -> List[Tuple]:
    sql = """
        SELECT a.package_name, a.target_sdk_version, ap.permission_name, ap.deprecated_in_api
        FROM apk_analysis a
        INNER JOIN vt_permissions vp ON a.analysis_id = vp.analysis_id
        INNER JOIN android_permissions ap ON vp.known_permission_id = ap.permission_id
        WHERE ap.deprecated_in_api IS NOT NULL AND ap.deprecated_in_api <= a.target_sdk_version
        ORDER BY a.target_sdk_version DESC, ap.permission_name;
    """
    return run_query(sql, is_select=True)

# Collect and list malware information including APK ID, names, family labels, and antivirus scan results
def get_malware_information() -> List[Tuple]:
    sql = """
        SELECT a.apk_id,
                m.name_1 'Name',
                m.name_2 AS Family,
                m.virustotal_label,
                s.AhnLab_V3,
                s.Alibaba,
                s.Ikarus,
                s.Kaspersky,
                s.microsoft,
                s.Tencent,
                s.ZoneAlarm
        FROM malware_ioc_threats m
        JOIN apk_samples a ON a.sha256 = m.sha256
        JOIN vt_scan_analysis s ON s.apk_id = a.apk_id
        ORDER BY a.apk_id;
    """
    return run_query(sql, is_select=True)

# Aggregate malware samples by month and family name to identify trends or outbreaks over time
def get_malware_samples_by_month() -> List[Tuple]:
    sql = """
        SELECT year,
            month,
            m.name_2,
            COUNT(*) AS num_samples
        FROM malware_ioc_threats m
            JOIN apk_samples a
                ON a.sha256 = m.sha256
            JOIN vt_scan_analysis s
                ON s.apk_id = a.apk_id
        GROUP BY year, month, m.name_2
        ORDER BY year DESC, month DESC, m.name_2;
        """
    return run_query(sql, is_select=True)

# Summarize permissions usage across different APK target SDK versions to understand adoption trends
def get_permissions_by_sdk_version() -> List[Tuple]:
    sql = """
        SELECT a.target_sdk_version, ap.permission_name, COUNT(*) AS usage_count
        FROM apk_analysis a
        INNER JOIN vt_permissions vp ON a.analysis_id = vp.analysis_id
        INNER JOIN android_permissions ap ON vp.known_permission_id = ap.permission_id
        GROUP BY a.target_sdk_version, ap.permission_name
        ORDER BY a.target_sdk_version DESC, usage_count DESC;
        """
    return run_query(sql, is_select=True)