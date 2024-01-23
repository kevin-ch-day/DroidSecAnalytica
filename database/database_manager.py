# database_manager.py

import mysql.connector
from contextlib import contextmanager
from utils import logging_utils

from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

# Context manager for database connections
@contextmanager
def database_connection():
    conn = None
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE
        )
        yield conn
    except mysql.connector.Error as e:
        logging_utils.log_error("Database connection failed", e)
        raise
    finally:
        if conn and conn.is_connected():
            conn.close()

# Execute SQL queries
def execute_query(query: str, params: tuple = None, fetch: bool = False):
    with database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        if fetch:
            return cursor.fetchall()
        else:
            conn.commit()

def execute_insert(table, data):
    try:
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['%s'] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        execute_query(query, tuple(data.values()), fetch=False)
        logging_utils.log_info("Insertion successful")
    except mysql.connector.Error as e:
        logging_utils.log_error("Error executing insert query", e)

def execute_update(table, data, condition):
    try:
        update_values = ', '.join([f"{key} = %s" for key in data.keys()])
        query = f"UPDATE {table} SET {update_values} WHERE {condition}"
        execute_query(query, tuple(data.values()), fetch=False)
        logging_utils.log_info("Update successful")
    except mysql.connector.Error as e:
        logging_utils.log_error("Error executing update query", e)

def execute_delete(table, condition):
    try:
        query = f"DELETE FROM {table} WHERE {condition}"
        execute_query(query, fetch=False)
        logging_utils.log_info("Deletion successful")
    except mysql.connector.Error as e:
        logging_utils.log_error("Error executing delete query", e)

def database_tables_info():
    try:
        result = execute_query("SHOW TABLES;", fetch=True)
        table_info = []
        for (table_name,) in result:
            num_columns = len(execute_query(f"SHOW COLUMNS FROM {table_name};", fetch=True))
            num_rows = execute_query(f"SELECT COUNT(*) FROM {table_name};", fetch=True)[0][0]

            # Calculate the size in MB for the table
            size_query = f"""
            SELECT table_schema 'Database',
                   ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 'Size in MB'
            FROM information_schema.TABLES
            WHERE table_schema = '{DB_DATABASE}' AND table_name = '{table_name}'
            GROUP BY table_schema, table_name;
            """
            size_result = execute_query(size_query, fetch=True)
            size_mb = size_result[0][1] if size_result else 0.0

            table_info.append((table_name, num_columns, num_rows, size_mb))
        return table_info
    except mysql.connector.Error as e:
        logging_utils.log_error("Error listing tables", e)
        return []

def test_database_connection():
    try:
        with database_connection() as conn:
            if conn.is_connected():
                print("Database connection successful.")
    except mysql.connector.Error as e:
        print("Database connection failed", e)

def empty_table(table_name):
    try:
        execute_query("SET FOREIGN_KEY_CHECKS = 0;", fetch=False)
        execute_query(f"TRUNCATE TABLE {table_name};", fetch=False)
        execute_query("SET FOREIGN_KEY_CHECKS = 1;", fetch=False)
        logging_utils.log_info(f"Table '{table_name}' has been successfully emptied.")
        return True
    except Exception as e:
        logging_utils.log_error(f"Error emptying table '{table_name}'", e)

def create_table(table_name, columns):
    try:
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})"
        execute_query(query, fetch=False)
        logging_utils.log_info(f"Table '{table_name}' created successfully.")
        return True
    except Exception as e:
        logging_utils.log_error(f"Error creating table '{table_name}'", e)
        return False

def drop_table(table_name):
    try:
        query = f"DROP TABLE IF EXISTS {table_name}"
        execute_query(query, fetch=False)
        logging_utils.log_info(f"Table '{table_name}' dropped successfully.")
        return True
    except Exception as e:
        logging_utils.log_error(f"Error dropping table '{table_name}'", e)
        return False
    
def get_disk_usage():
    try:
        query = """
        SELECT table_schema 'Database',
               ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 'Size in MB'
        FROM information_schema.TABLES
        WHERE table_schema = '{}'
        GROUP BY table_schema;
        """.format(DB_DATABASE)
        return execute_query(query, fetch=True)
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching disk usage", e)
        return []

# New function to get database information
def get_database_info():
    try:
        with database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION();")
            version = cursor.fetchone()
            cursor.execute("SHOW STATUS LIKE 'Uptime';")
            uptime = cursor.fetchone()
            cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
            connections = cursor.fetchone()
            return version, uptime, connections
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching database information", e)
        return None

# New function to get thread information
def get_thread_information():
    try:
        query = "SHOW STATUS LIKE 'Threads_%';"
        return execute_query(query, fetch=True)
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching thread information", e)
        return []

# New function to get query statistics
def get_query_statistics():
    try:
        query = "SHOW STATUS LIKE 'Queries';"
        return execute_query(query, fetch=True)
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching query statistics", e)
        return []