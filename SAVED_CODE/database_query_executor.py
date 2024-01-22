# database_query_executor.py

from . import database_manager, database_utils
import logging
import mysql.connector

def check_for_table(table_name):
    sql = "SHOW TABLES LIKE %s;"
    result = database_manager.execute_query(sql, (table_name,), fetchone=True)
    return bool(result)

def insert_data(table_name, data):
    placeholders = ', '.join(['%s'] * len(data))
    sql = f"INSERT INTO {table_name} VALUES ({placeholders})"
    return database_manager.execute_query(sql, data)

def update_data(table_name, data, conditions):
    set_clause = ', '.join([f"{key} = %s" for key in data])
    condition_clause = ' AND '.join([f"{key} = %s" for key in conditions])
    sql = f"UPDATE {table_name} SET {set_clause} WHERE {condition_clause}"
    values = list(data.values()) + list(conditions.values())
    return database_manager.execute_query(sql, values)

def delete_data(table_name, conditions):
    condition_clause = ' AND '.join([f"{key} = %s" for key in conditions])
    sql = f"DELETE FROM {table_name} WHERE {condition_clause}"
    values = list(conditions.values())
    return database_manager.execute_query(sql, values)

def select_data(table_name, columns, conditions=None):
    column_clause = ', '.join(columns)
    sql = f"SELECT {column_clause} FROM {table_name}"
    values = None
    if conditions:
        condition_clause = ' AND '.join([f"{key} = %s" for key in conditions])
        sql += f" WHERE {condition_clause}"
        values = list(conditions.values())
    return database_manager.execute_query(sql, values, fetch=True)

def execute_batch(sql, values_list):
    with database_manager.database_connection() as conn:
        if conn is None:
            return False
        try:
            cursor = conn.cursor()
            for values in values_list:
                cursor.execute(sql, values)
            conn.commit()
            return True
        except mysql.connector.Error as error:
            logging.error(f"Error executing batch SQL queries: {error}")
            conn.rollback()
            return False
        finally:
            if cursor:
                cursor.close()

def run_sql(sql, values=None, fetch=False):
    with database_manager.database_connection() as conn:
        return database_manager.execute_query(conn, sql, values, fetch)


def display_database_info(conn):
    try:
        cursor = conn.cursor()
        # Display the database version
        cursor.execute("SELECT VERSION();")
        version = cursor.fetchone()
        print(f"Database Version: {version[0]}")

        # Display the server uptime
        cursor.execute("SHOW STATUS LIKE 'Uptime';")
        uptime = cursor.fetchone()
        formatted_uptime = database_utils.format_seconds_to_dhms(int(uptime[1]))
        print(f"Server Uptime: {formatted_uptime}")

        # Display the number of active connections
        cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
        connections = cursor.fetchone()
        print(f"Active Connections: {connections[1]}")

        # Any other relevant database info can be added here
    except mysql.connector.Error as e:
        logging.error(f"Error displaying database info: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while displaying database info: {e}")


def display_performance_metrics(conn):
    try:
        cursor = conn.cursor()
        # Display total number of queries executed
        cursor.execute("SHOW STATUS LIKE 'Queries';")
        query_count = cursor.fetchone()
        print(f"Total Queries executed: {query_count[1]}")

        cursor.execute("SHOW STATUS LIKE 'Threads_running';")
        threads_running = cursor.fetchone()
        print(f"Threads Running: {threads_running[1]}")

        # Additional metrics can be added here
    except mysql.connector.Error as e:
        logging.error(f"Error displaying performance metrics: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while displaying performance metrics: {e}")



def update_records_no_virustotal_match(record_id):
    try:
        conn = database_manager.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = "UPDATE android_malware_hashes SET no_virustotal_match = 1 WHERE id = %s"
                cursor.execute(sql, (record_id,))
                conn.commit()
                if cursor.rowcount > 0:
                    print(f"Database record updated.")
                else:
                    print(f"Database record not updated. Exiting...")
    except Exception as e:
        print(f"Error updating record ID {record_id}: {e}")
    finally:
        if conn:
            conn.close()


def get_total_hash_records():
    conn = database_manager.connect_to_database()
    if conn:
        with conn.cursor() as cursor:
            print("Fetching records from the database...")
            cursor.execute("SELECT * FROM android_malware_hashes")
            records = cursor.fetchall()
            total_records = len(records)
            print(f"Total records: {total_records}")
    
    return records


def check_for_hash_record(hash_dict):
    try:
        conn = database_manager.connect_to_database()
        if conn:
            with conn.cursor() as cursor:
                sql = "SELECT id, md5, sha1, sha256 FROM malware_hashes "
                sql += f"where md5 = {hash_dict['MD5']} or sha1 = {hash_dict['SHA1']} or sha256 = {hash_dict['SHA256']} "
                sql += "order by id"
                cursor.execute(sql)
                result = cursor.fetchall()
                if result:
                    return True
                else:
                    return False
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()


def check_if_hash_analyzed(hash_dict):
    hash_record_id = []
    try:
        conn = database_manager.connect_to_database()
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
        conn = database_manager.connect_to_database()
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
def get_intent_filters(is_unusual=True):
    try:
        conn = database_manager.connect_to_database()
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

