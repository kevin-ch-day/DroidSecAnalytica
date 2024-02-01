# DBFunctions.py

from . import DBConnectionManager as dbConnect

def get_apk_samples():
    query = "SELECT * FROM apk_samples order by apk_id"
    return dbConnect.execute_query(query, fetch=True)

def get_apk_samples_sha256():
    query = """
    SELECT apk_id, sha256 FROM apk_samples ORDER BY apk_id
    """
    return dbConnect.execute_query(query, fetch=True)

def get_malware_hash_samples():
    query = "SELECT * FROM malware_threat_metadata"
    return dbConnect.execute_query(query, fetch=True)

def update_apk_record(record_id, data):
    table = "apk_samples"
    condition = "sample_id = %s"
    dbConnect.execute_update(table, data, condition, params=(record_id,))

def get_permission_id_by_name(perm_name):
    query = """
    SELECT permission_id FROM android_permissions WHERE constant_value = %s
    """
    params = (perm_name,)
    result = dbConnect.execute_query(query, params, fetch=True)
    return result[0][0] if result else None

def get_unknown_permission_id(perm_name):
    query = "SELECT permission_id FROM unknown_android_permissions WHERE constant_value = %s"
    params = (perm_name,)
    result = dbConnect.execute_sql(query, params, fetch=True)
    return result[0][0] if result else None