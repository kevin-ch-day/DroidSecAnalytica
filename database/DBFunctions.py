# DBFunctions.py

from . import DBConnectionManager as dbConnect

def get_apk_samples():
    query = "SELECT * FROM apk_samples order by apk_id"
    return dbConnect.execute_query(query, fetch=True)

def get_apk_samples_sha256():
    query = "SELECT apk_id, file_name, sha256 FROM apk_samples "
    query += "where android_malware = 1 order by apk_id"
    return dbConnect.execute_query(query, fetch=True)

def get_malware_hash_samples():
    query = "SELECT * FROM malware_threat_metadata"
    return dbConnect.execute_query(query, fetch=True)

def update_apk_record(record_id, data):
    table = "apk_samples"
    condition = "sample_id = %s"
    dbConnect.execute_update(table, data, condition, params=(record_id,))