# database_manager.py

import mysql.connector
from contextlib import contextmanager
from utils import logging_utils

from database.DBConfig import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

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

# Insert into database tables
def execute_insert(table, data):
    try:
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['%s'] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        execute_query(query, tuple(data.values()), fetch=False)
        logging_utils.log_info("Insertion successful")
    except mysql.connector.Error as e:
        logging_utils.log_error("Error executing insert query", e)

# Update database tables
def execute_update(table, data, condition):
    try:
        update_values = ', '.join([f"{key} = %s" for key in data.keys()])
        query = f"UPDATE {table} SET {update_values} WHERE {condition}"
        execute_query(query, tuple(data.values()), fetch=False)
        logging_utils.log_info("Update successful")
    except mysql.connector.Error as e:
        logging_utils.log_error("Error executing update query", e)

# Delete from database tables
def execute_delete(table, condition):
    try:
        query = f"DELETE FROM {table} WHERE {condition}"
        execute_query(query, fetch=False)
        logging_utils.log_info("Deletion successful")
    except mysql.connector.Error as e:
        logging_utils.log_error("Error executing delete query", e)

# Test database connection
def test_connection():
    try:
        with database_connection() as conn:
            if conn.is_connected():
                print("Database connection successful.")
    except mysql.connector.Error as e:
        print("Database connection failed", e)

# Empty database table
def empty_table(table_name):
    try:
        execute_query("SET FOREIGN_KEY_CHECKS = 0;", fetch=False)
        execute_query(f"TRUNCATE TABLE {table_name};", fetch=False)
        execute_query("SET FOREIGN_KEY_CHECKS = 1;", fetch=False)
        print(f"Table '{table_name}' has been successfully emptied.")
        return True
    except Exception as e:
        logging_utils.log_error(f"Error emptying table '{table_name}'", e)

# Create database table
def create_table(table_name, columns):
    try:
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})"
        execute_query(query, fetch=False)
        logging_utils.log_info(f"Table '{table_name}' created successfully.")
        return True
    except Exception as e:
        logging_utils.log_error(f"Error creating table '{table_name}'", e)
        return False

# Drop database table
def drop_table(table_name):
    try:
        query = f"DROP TABLE IF EXISTS {table_name}"
        execute_query(query, fetch=False)
        logging_utils.log_info(f"Table '{table_name}' dropped successfully.")
        return True
    except Exception as e:
        logging_utils.log_error(f"Error dropping table '{table_name}'", e)
        return False