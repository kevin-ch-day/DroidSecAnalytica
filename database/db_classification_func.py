# db_classification_func.py

from . import db_conn

def get_malware_classification(sha256):
    # Retrieves malware classification information for a given SHA-256 hash.
    sql = """
        SELECT m.id,
               m.name_1 AS Name,
               m.name_2 AS Family,
               m.virustotal_label,
               s.AhnLab_V3,
               s.Alibaba,
               s.Ikarus,
               s.Kaspersky,
               s.microsoft,
               s.Tencent,
               s.ZoneAlarm
        FROM malware_samples m
        JOIN vt_scan_analysis s ON s.apk_id = m.id
        WHERE m.sha256 = %s
        ORDER BY m.id
    """
    params = (sha256,)  # Parameters passed in a tuple

    try:
        results = db_conn.execute_query(sql, params=params, fetch=True)
        return results
    
    except Exception as e:
        print(f"Error fetching malware classification: {e}")
        return []

def add_vt_engine_column(new_vt_engine, data_type="VARCHAR(100)"):
    # Ensure the new column name is a string and appropriate
    if not isinstance(new_vt_engine, str) or not new_vt_engine.strip():
        raise ValueError("Invalid vt engine name.")

    # Check if the column already exists
    existing_columns = db_conn.execute_query("SHOW COLUMNS FROM vt_scan_analysis", fetch=True)
    if any(col[0] == new_vt_engine for col in existing_columns):
        raise ValueError(f"Column: '{new_vt_engine}' already exists.")

    try:
        sql = f"ALTER TABLE vt_scan_analysis ADD COLUMN {new_vt_engine} {data_type} AFTER type_unsupported;"
        db_conn.execute_query(sql, fetch=False)
        print(f"New vt_engine column \"{new_vt_engine}\" added successfully.")
    
    except Exception as e:
        print(f"Failed to add new vt_engine column \"{new_vt_engine}\": {e}")

def create_malware_project_mapping(malware_id, droidsecanalytica, family, md5):
    report_id = 0
    classification = droidsecanalytica
    
    try:
        sql = "UPDATE malware_project_mapping SET droidsecanalytica_label = %s WHERE malware_id = %s;"
        params = (malware_id, report_id, droidsecanalytica, family, md5)
        db_conn.execute_query(sql, params=params, fetch=False)

    except Exception as e:
        print(f"Failed to update malware_project_mapping for malware id: {malware_id}")
        print(f"Exception: {e}")
