# db_conn.py

import mysql.connector
from contextlib import contextmanager
from utils import logging_utils
from database.db_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE
import pandas as pd

logger = logging_utils.get_logger(__name__)

@contextmanager
def database_connection():
    conn = None
    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_DATABASE, autocommit=False)
        yield conn
    except mysql.connector.Error:
        logger.exception("Database connection failed")
        if conn:
            conn.rollback()
        raise
    else:
        conn.commit()
    finally:
        if conn and conn.is_connected():
            conn.close()

def get_database_connection():
    conn = None
    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_DATABASE)
    except mysql.connector.Error:
        logger.exception("Database connection failed")
    return conn

def execute_query(query: str, params: tuple = None, fetch: bool = False):
    with database_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        if fetch:
            return cursor.fetchall()
        
        conn.commit()

def execute_insert(table, data):
    try:
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['%s'] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        execute_query(query, tuple(data.values()), fetch=False)
        logger.info("Insertion successful")
    except mysql.connector.Error:
        logger.exception("Error executing insert query")

def execute_update(table, data, condition):
    try:
        update_values = ', '.join([f"{key} = %s" for key in data.keys()])
        query = f"UPDATE {table} SET {update_values} WHERE {condition}"
        execute_query(query, tuple(data.values()), fetch=False)
        logger.info("Update successful")
    except mysql.connector.Error:
        logger.exception("Error executing update query")

def execute_delete(table, condition):
    try:
        query = f"DELETE FROM {table} WHERE {condition}"
        execute_query(query, fetch=False)
        logger.info("Deletion successful")
    except mysql.connector.Error:
        logger.exception("Error executing delete query")

def test_connection():
    conn = None
    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_DATABASE)
        print("Database connection successful.")
    except mysql.connector.Error as e:
        print("Database connection failed")
    finally:
        if conn and conn.is_connected():
            conn.close()

def empty_table(table_name):
    try:
        execute_query("SET FOREIGN_KEY_CHECKS = 0;", fetch=False)
        execute_query(f"TRUNCATE TABLE {table_name};", fetch=False)
        execute_query("SET FOREIGN_KEY_CHECKS = 1;", fetch=False)
        logger.info("Table '%s' has been successfully emptied.", table_name)
    except Exception:
        logger.exception("Error emptying table '%s'", table_name)

def create_table(table_name, columns):
    try:
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})"
        execute_query(query, fetch=False)
        logger.info("Table '%s' created successfully.", table_name)
    except Exception:
        logger.exception("Error creating table '%s'", table_name)

def drop_table(table_name):
    try:
        query = f"DROP TABLE IF EXISTS {table_name}"
        execute_query(query, fetch=False)
        logger.info("Table '%s' dropped successfully.", table_name)
    except Exception:
        logger.exception("Error dropping table '%s'", table_name)

def execute_query_with_params(query, params):
    try:
        return pd.DataFrame(execute_query(query, params=params, fetch=True))
    except Exception as e:
        print(f"An error occurred during query execution: {str(e)}")
        return None

def handle_errors(e):
    print(f"An error occurred during query execution: {str(e)}")

def generate_df_from_query(query, params=None, debugging=False):
    try:
        df = execute_query_with_params(query, params)

        if df.empty:
            if debugging:
                print(f"No data available for query: {query}.")
            return None

        return df

    except Exception as e:
        handle_errors(e)
        return None
