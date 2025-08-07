# db_insert_records.py

from typing import Optional
from database import db_conn as dbConnect
from utils import logging_utils

logger = logging_utils.get_logger(__name__)

# Execute SQL queries
def execute_sql(query: str, params: Optional[tuple] = None, should_fetch: bool = False) -> Optional[any]:
    try:
        result = dbConnect.execute_query(query, params, fetch=should_fetch)
        return result if should_fetch else True
    except Exception:
        logger.exception("Error executing query: %s", query)
        return None

# Function to insert data into vt_permissions table
def insert_vt_permission(analysis_id: int, apk_id: int, standard_perm_id: Optional[int], unknown_perm_id: Optional[int], manuf_perm_id: Optional[int]) -> Optional[bool]:
    query = "INSERT INTO vt_permissions (analysis_id, apk_id, known_permission_id, unknown_permission_id, manufacturer_permission_id)"
    query += " VALUES (%s, %s, %s, %s, %s)"
    params = (analysis_id, apk_id, standard_perm_id, unknown_perm_id, manuf_perm_id)
    return execute_sql(query, params)

# Insert a new unknown permission record
def insert_new_unknown_permission(index) -> Optional[bool]:
    query = "INSERT INTO unknown_permissions (constant_value, protection_level, andro_short_desc, andro_long_desc) VALUES (%s, %s, %s, %s, %s)"
    params = (index.name, index.permission_type, index.short_desc, index.long_desc)
    return execute_sql(query, params)

# Insert a new android permission record more concisely
def insert_android_permission_v2(constant_value: str) -> Optional[bool]:
    # This handles cases with or without the "android.permission." prefix
    permission_name = constant_value.split('.')[-1]
    query = "INSERT INTO android_permissions (permission_name, constant_value) VALUES (%s, %s)"
    params = (permission_name, constant_value)
    return execute_sql(query, params)

def insert_vt_activities(analysis_id: int, activity_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_activities (analysis_id, activity_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, activity_name, apk_id)
    return execute_sql(query, params)

def insert_vt_libraries(analysis_id: int, library_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_libraries (analysis_id, library_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, library_name, apk_id)
    return execute_sql(query, params)

def insert_vt_services(analysis_id: int, service_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_services (analysis_id, service_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, service_name, apk_id)
    return execute_sql(query, params)

def insert_vt_receivers(analysis_id: int, receiver_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_receivers (analysis_id, receiver_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, receiver_name, apk_id)
    return execute_sql(query, params)

def insert_vt_providers(analysis_id: int, provider_name: str, apk_id: int) -> Optional[bool]:
    query = "INSERT INTO vt_providers (analysis_id, provider_name, apk_id) VALUES (%s, %s, %s)"
    params = (analysis_id, provider_name, apk_id)
    return execute_sql(query, params)

# Insert hash records into the hash_data_ioc table
def add_hash_ioc_record(md5: str, sha1: str, sha256: str) -> Optional[bool]:
    # Ensure all hash values are provided
    if not md5 or not sha1 or not sha256:
        print("[ERROR] All hash values (MD5, SHA1, SHA256) must be provided.")
        return None

    # Construct the query
    query = "INSERT INTO hash_data_ioc (md5, sha1, sha256) VALUES (%s, %s, %s)"
    params = (md5, sha1, sha256)

    # Execute the query
    try:
        result = execute_sql(query, params)
        return result
    except Exception as e:
        print(f"[ERROR] Error executing query: {e}")
        return None

# Insert hash data into the hash_data_ioc table
def insert_hash_data(md5: Optional[str], sha1: Optional[str], sha256: Optional[str]) -> Optional[bool]:
    # Ensure at least one hash value is provided
    if not (md5 or sha1 or sha256):
        print("[ERROR] No valid hash provided for insertion.")
        return None

    # Prepare query and parameters dynamically based on the hash values provided
    values = params = columns = []

    if md5:
        columns.append("md5")
        values.append("%s")
        params.append(md5)

    if sha1:
        columns.append("sha1")
        values.append("%s")
        params.append(sha1)

    if sha256:
        columns.append("sha256")
        values.append("%s")
        params.append(sha256)

    # Construct the query dynamically based on available hash data
    columns_str = ", ".join(columns)
    values_str = ", ".join(values)
    query = f"INSERT INTO hash_data_ioc ({columns_str}) VALUES ({values_str})"

    # Execute the query
    try:
        result = execute_sql(query, tuple(params))
        return result
    except Exception as e:
        print(f"[ERROR] Error executing query: {e}")
        return None

# Insert a malware sample record into the malware_samples table
def store_malware_sample(
    malware_name: str,
    malware_family: str,
    vt_threat_label: str,
    md5_hash: str,
    sha1_hash: str,
    sha256_hash: str,
    raw_size_bytes: int,
    formatted_size: str,
    first_seen_wild: str,
    first_submission: str,
    file_type_description: str,
    vt_report_url: str
) -> bool:
    # Validate that all essential hash values are provided
    if not (md5_hash and sha1_hash and sha256_hash):
        print("[ERROR] Missing hash values. MD5, SHA1, and SHA256 are required.")
        return False

    # Define SQL query
    query = """
    INSERT INTO malware_samples (
        malware_name, malware_family, virustotal_label, md5, sha1, sha256, sample_size, formatted_sample_size, 
        vt_first_seen_wild, vt_first_submission, data_type_description, virustotal_url
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    # Prepare parameters
    params = (
        malware_name, malware_family, vt_threat_label, md5_hash, sha1_hash, sha256_hash,
        raw_size_bytes, formatted_size, first_seen_wild, first_submission, file_type_description, vt_report_url
    )

    # Execute query
    try:
        result = execute_sql(query, params)
        return bool(result)
    except Exception as e:
        print(f"[ERROR] Failed to insert malware sample: {e}")
        return False
