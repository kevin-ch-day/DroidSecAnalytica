import logging
from database import database_core, database_functions
from utils import app_utils

def loadAndroidHashData():
    try:
        if not database_functions.check_android_malware_hash_table_exists():
            database_functions.create_android_malware_hash_table()
        
        files_to_parse = ['input/2019-README.txt',
                          'input/2020-README.txt',
                         'input/2021-README.txt',
                         'input/2022-README.txt']

        load_data_from_files(files_to_parse)
        print(f"Data processing completed.")

    except Exception as e:
        logging.error(f"Error during data processing: {e}")

def load_data_from_files(files_to_parse):
    try:
        with database_core.connect_to_database() as conn, conn.cursor() as cursor:
            for file in files_to_parse:
                parsed_data = app_utils.parse_file(file)
                if not parsed_data:
                    print(f"No valid data parsed from {file}.")
                    continue

                sql_insert_data = "INSERT INTO android_malware_hashes (malware_category, md5, sha1, sha256, location, month) VALUES (%s, %s, %s, %s, %s, %s)"
                cursor.executemany(sql_insert_data, parsed_data)
                conn.commit()
                print(f"Data from {file} inserted successfully.")
                print(f"Total records inserted: {len(parsed_data)}\n")
    except Exception as e:
        logging.error(f"Error in load_data_from_files: {e}")
        print(f"Error occurred while processing file {file}.")

def viewAndroidHashTableSummary():
    conn = database_core.connect_to_database()
    cursor = conn.cursor()
    sql = "SELECT COUNT(*) FROM android_malware_hashes"
    result = database_core.execute_sql(cursor, sql)
    print(f"Total Records in Database: {result[0][0]}")
    database_core.close_database_connection(conn)