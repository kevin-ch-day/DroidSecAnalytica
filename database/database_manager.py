import mysql.connector
import logging
from contextlib import contextmanager
from typing import Optional

from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

# Utility function for logging errors
def log_error(message: str, error: Optional[Exception] = None):
    if error:
        logging.error(f"{message}: {error}")
    else:
        logging.error(message)

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
        log_error("Database connection failed", e)
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
        logging.info("Insertion successful")
    except mysql.connector.Error as e:
        log_error("Error executing insert query", e)

def execute_update(table, data, condition):
    try:
        update_values = ', '.join([f"{key} = %s" for key in data.keys()])
        query = f"UPDATE {table} SET {update_values} WHERE {condition}"
        execute_query(query, tuple(data.values()), fetch=False)
        logging.info("Update successful")
    except mysql.connector.Error as e:
        log_error("Error executing update query", e)

def execute_delete(table, condition):
    try:
        query = f"DELETE FROM {table} WHERE {condition}"
        execute_query(query, fetch=False)
        logging.info("Deletion successful")
    except mysql.connector.Error as e:
        log_error("Error executing delete query", e)

def list_tables():
    try:
        result = execute_query("SHOW TABLES;", fetch=True)
        table_info = []
        for (table_name,) in result:
            num_columns = len(execute_query(f"SHOW COLUMNS FROM {table_name};", fetch=True))
            num_rows = execute_query(f"SELECT COUNT(*) FROM {table_name};", fetch=True)[0][0]
            table_info.append((table_name, num_columns, num_rows))
        return table_info
    except mysql.connector.Error as e:
        log_error("Error listing tables", e)
        return []

def display_tables_info():
    tables_info = list_tables()
    if not tables_info:
        log_error("No table information available or failed to retrieve table information.")
        return

    print("\nDatabase Tables Information:")
    print(f"{'Table Name'.ljust(30)} | {'# of Columns'.rjust(15)} | {'# of Rows'.rjust(15)}")
    print("-" * 65)
    
    for table_name, num_columns, num_rows in tables_info:
        print(f"{table_name.ljust(30)} | {str(num_columns).rjust(15)} | {str(num_rows).rjust(15)}")

# Test the database connection
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
        logging.info(f"Table '{table_name}' has been successfully emptied.")
        return True
    except Exception as e:
        log_error(f"Error emptying table '{table_name}'", e)
        return False