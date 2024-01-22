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

# Function to execute SQL queries
def execute_query(query: str, params: tuple = None, fetch: bool = False):
    with database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        if fetch:
            return cursor.fetchall()
        else:
            conn.commit()

# Functions for insert, update, and delete operations
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