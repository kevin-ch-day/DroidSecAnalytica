import mysql.connector
import logging
from typing import Dict

from . import database_manager as dbConnect

def check_if_hash_analyzed(hash_dict):
    try:
        sql = "SELECT id, md5, sha1, sha256 FROM malware_hashes WHERE md5 = %s OR sha1 = %s OR sha256 = %s ORDER BY id"
        params = (hash_dict['MD5'], hash_dict['SHA1'], hash_dict['SHA256'])
        result = dbConnect.execute_query(sql, params, fetch=True)
        return bool(result)
    except Exception as e:
        dbConnect.log_error("Error checking if hash is analyzed", e)
        return False

def get_total_records_to_process():
    try:
        sql = """
            SELECT COUNT(*) FROM android_malware_hashes
            WHERE id NOT IN (SELECT id FROM android_malware_hashes WHERE no_virustotal_match = 1)
            AND (md5 IS NULL OR sha1 IS NULL OR sha256 IS NULL);
        """
        result = dbConnect.execute_query(sql, fetch=True)
        return result[0][0] if result else 0
    except Exception as e:
        dbConnect.log_error("Error getting total records to process", e)
        return 0

def create_apk_record(filename, filesize, md5, sha1, sha256):
    try:
        sql = "INSERT INTO apk_samples (filename, filesize, md5, sha1, sha256) VALUES (%s, %s, %s, %s, %s)"
        values = (filename, filesize, md5, sha1, sha256)
        dbConnect.execute_query(sql, values)
        logging.info("APK record created successfully.")
    except Exception as e:
        dbConnect.log_error("Error creating APK record", e)

def insert_data_into_malware_hashes(file_path, data):
    try:
        sql_insert_data = """
            INSERT INTO malware_hashes 
            (name_1, name_2, md5, sha1, sha256, location, month, year)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        for record in data:
            dbConnect.execute_query(sql_insert_data, record)
        logging.info(f"Data from {file_path} inserted successfully. Total records: {len(data)}")
    except Exception as e:
        dbConnect.log_error(f"Error inserting record from {file_path}", e)

def get_intent_filters(is_unusual=True):
    try:
        sql = "SELECT * FROM android_intent_filters WHERE IsUnusual = %s"
        params = (1 if is_unusual else 0,)
        results = dbConnect.execute_query(sql, params, fetch=True)
        return results if results else []
    except Exception as e:
        dbConnect.log_error("Error fetching intent filters", e)
        return []

def get_intent_filter_record_by_name(intent_name: str) -> Dict:
    try:
        sql = "SELECT * FROM android_intent_filters WHERE IntentName = %s"
        params = (intent_name,)
        result = dbConnect.execute_query(sql, params, fetch=True)
        return result[0] if result else None
    except Exception as e:
        dbConnect.log_error(f"Error fetching intent filter record for {intent_name}", e)
        return None