# database_utils_3

import mysql.connector
from mysql.connector import Error
import logging
from contextlib import contextmanager
from typing import Dict, List

from . import other_utils, database_manager as dbConnect

# Context manager for database connection
@contextmanager
def database_connection():
    conn = dbConnect.connect_to_database()
    try:
        yield conn
    finally:
        dbConnect.close_database_connection(conn)

def check_if_hash_analyzed(hash_dict):
    hash_record_id = []
    try:
        conn = dbConnect.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = "SELECT id, md5, sha1, sha256 FROM malware_hashes "
                sql += f"where md5 = {hash_dict['MD5']} or sha1 = {hash_dict['SHA1']} or sha256 = {hash_dict['SHA256']} "
                sql += "order by id"
                cursor.execute(sql)
                result = cursor.fetchall()
                if result:
                    for x in result:
                        hash_record_id.append(x)
                        if len(hash_record_id) == 0:
                            return False
                        else:
                            return True
                else:
                    return False
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def get_total_records_to_process():
    try:
        conn = dbConnect.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = """
                    SELECT COUNT(*) FROM android_malware_hashes
                    WHERE id NOT IN (SELECT id FROM android_malware_hashes WHERE no_virustotal_match = 1)
                    AND (md5 IS NULL OR sha1 IS NULL OR sha256 IS NULL);
                """
                cursor.execute(sql)
                result = cursor.fetchone()
                if result:
                    return result[0]
                else:
                    return 0
    except Exception as e:
        print(f"Error counting records with no match: {e}")
    finally:
        conn.close()

# Create apk sample record
def create_apk_record(filename, filesize, md5, sha1, sha256):
    sql = "INSERT INTO apk_samples (...) VALUES (%s, %s, %s, %s, %s)"
    values = (filename, filesize, md5, sha1, sha256)
    run_sql(sql, values)

def insert_data_into_malware_hashes(file_path, data):
    """ Insert parsed data into the database. """
    sql_insert_data = """
        INSERT INTO malware_hashes 
        (name_1, name_2, md5, sha1, sha256, location, month, year)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    for record in data:
        try:
            run_sql(sql_insert_data, record)
        except Exception as e:
            logging.error(f"Error inserting record from {file_path}: {e}")
            logging.error(f"Problematic record: {record}")

    logging.info(f"Data from {file_path} inserted successfully. Total records: {len(data)}")

def get_intent_filters(is_unusual=True):
    try:
        conn = dbConnect.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = "SELECT * FROM android_intent_filters x WHERE x.IsUnusual = %s"
                cursor.execute(sql, (1 if is_unusual else 0,))
                results = cursor.fetchall()
                return results if results else []
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

    return False  # Return False if no unusual intent filter found

def get_intent_filter_record_by_name(intent_name: str) -> Dict:
    """Get an intent filter by its name."""
    cursor = cursor(dictionary=True)
    query = "SELECT * FROM android_intent_filters WHERE IntentName = %s"
    cursor.execute(query, (intent_name,))
    result = cursor.fetchone()
    cursor.close()
    return result
