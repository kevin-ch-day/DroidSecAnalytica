# db_conn.py

import mysql.connector
from mysql.connector import Error
from contextlib import contextmanager
from utils import logging_utils
from . import db_config

logger = logging_utils.get_logger(__name__)

@contextmanager
def database_connection():
    conn = None
    try:
        conn = mysql.connector.connect(host=db_config.DB_HOST, user=db_config.DB_USER, password=db_config.DB_PASSWORD, database=db_config.DB_DATABASE, autocommit=False)
        yield conn
    except mysql.connector.Error as e:
        logger.error("Database connection failed", exc_info=e)
        if conn:
            conn.rollback()
        raise
    else:
        conn.commit()
    finally:
        if conn and conn.is_connected():
            conn.close()

def execute_query(query: str, params: tuple = None, fetch: bool = False):
    with database_connection() as conn:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute(query, params or ())
            if fetch:
                return cursor.fetchall()
            conn.commit()
            return True

def execute_insert(table, data):
    try:
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['%s'] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        return execute_query(query, tuple(data.values()), fetch=False)
    except mysql.connector.Error as e:
        logger.error("Error executing insert query", exc_info=e)
        return False

def execute_update(table, data, condition):
    try:
        update_values = ', '.join([f"{key} = %s" for key in data.keys()])
        query = f"UPDATE {table} SET {update_values} WHERE {condition}"
        return execute_query(query, tuple(data.values()), fetch=False)
    except mysql.connector.Error as e:
        logger.error("Error executing update query", exc_info=e)
        return False

def execute_delete(table, condition):
    try:
        query = f"DELETE FROM {table} WHERE {condition}"
        return execute_query(query, fetch=False)
    except mysql.connector.Error as e:
        logger.error("Error executing delete query", exc_info=e)
        return False

def empty_table(table_name):
    try:
        execute_query("SET FOREIGN_KEY_CHECKS = 0;", fetch=False)
        execute_query(f"TRUNCATE TABLE {table_name};", fetch=False)
        execute_query("SET FOREIGN_KEY_CHECKS = 1;", fetch=False)
        logger.info("Table '%s' has been successfully emptied.", table_name)
        return True
    except Exception as e:
        logger.error("Error emptying table '%s'", table_name, exc_info=e)
        return False

def create_table(table_name, columns):
    try:
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})"
        if execute_query(query, fetch=False):
            logger.info("Table '%s' created successfully.", table_name)
            return True
    except Exception as e:
        logger.error("Error creating table '%s'", table_name, exc_info=e)
        return False

def drop_table(table_name):
    try:
        query = f"DROP TABLE IF EXISTS {table_name}"
        if execute_query(query, fetch=False):
            logger.info("Table '%s' dropped successfully.", table_name)
            return True
    except Exception as e:
        logger.error("Error dropping table '%s'", table_name, exc_info=e)
        return False
