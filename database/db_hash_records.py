from typing import Dict
from utils import logging_utils
from . import db_manager as dbConnect

def viewAndroidHashTableSummary():
    try:
        result = dbConnect.execute_query("SELECT COUNT(*) FROM android_malware_hashes", fetch=True)
        if result:
            print(f"Total Records in Database: {result[0][0]}")
        else:
            print("Failed to retrieve hash table summary.")
    except Exception as e:
        logging_utils.log_error("Error retrieving hash table summary", e)

def get_total_hash_records():
    try:
        records = dbConnect.execute_query("SELECT * FROM android_malware_hashes", fetch=True)
        total_records = len(records)
        print(f"Total records: {total_records}")
        return records
    except Exception as e:
        dbConnect.log_error("Error fetching total hash records", e)
        return []

def check_if_hash_analyzed(hash_dict: Dict[str, str]) -> bool:
    try:
        sql = "SELECT id FROM malware_hashes WHERE md5 = %s OR sha1 = %s OR sha256 = %s"
        params = (hash_dict['MD5'], hash_dict['SHA1'], hash_dict['SHA256'])
        result = dbConnect.execute_query(sql, params, fetch=True)
        return bool(result)
    except Exception as e:
        logging_utils.log_error("Error checking if hash is analyzed", e)
        return False

def check_for_hash_record(hash_dict):
    try:
        sql = """
            SELECT id, md5, sha1, sha256 
            FROM android_malware_hashes 
            WHERE md5 = %s OR sha1 = %s OR sha256 = %s 
            ORDER BY id
        """
        params = (hash_dict['MD5'], hash_dict['SHA1'], hash_dict['SHA256'])
        result = dbConnect.execute_query(sql, params, fetch=True)
        return bool(result)
    except Exception as e:
        dbConnect.log_error("Error checking for hash record", e)
        return False

def insert_data_into_malware_hashes(file_path: str, data: list):
    try:
        sql_insert_data = """
            INSERT INTO malware_hashes 
            (name_1, name_2, md5, sha1, sha256, location, month, year)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        for record in data:
            dbConnect.execute_query(sql_insert_data, record)
        logging_utils.log_info(f"Data from {file_path} inserted successfully. Total records: {len(data)}")
    except Exception as e:
        logging_utils.log_error(f"Error inserting record from {file_path}", e)

def get_total_records_to_process() -> int:
    try:
        sql = """
            SELECT COUNT(*) FROM android_malware_hashes
            WHERE id NOT IN (SELECT id FROM android_malware_hashes WHERE no_virustotal_match = 1)
            AND (md5 IS NULL OR sha1 IS NULL OR sha256 IS NULL);
        """
        result = dbConnect.execute_query(sql, fetch=True)
        return result[0][0] if result else 0
    except Exception as e:
        logging_utils.log_error("Error getting total records to process", e)
        return 0