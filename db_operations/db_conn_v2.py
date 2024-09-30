# db_conn.py

import mysql.connector
from mysql.connector import Error
from contextlib import contextmanager
from . import db_config

@contextmanager
def database_connection():
    conn = None
    try:
        conn = mysql.connector.connect(host=db_config.DB_HOST, user=db_config.DB_USER, password=db_config.DB_PASSWORD, database=db_config.DB_DATABASE, autocommit=False)
        yield conn
    except mysql.connector.Error as e:
        print("Database connection failed", e)
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
        cursor = conn.cursor(dictionary=True)
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
        print("Error executing insert query", e)
        return False

def execute_update(table, data, condition):
    try:
        update_values = ', '.join([f"{key} = %s" for key in data.keys()])
        query = f"UPDATE {table} SET {update_values} WHERE {condition}"
        return execute_query(query, tuple(data.values()), fetch=False)
    except mysql.connector.Error as e:
        print("Error executing update query", e)
        return False

def execute_delete(table, condition):
    try:
        query = f"DELETE FROM {table} WHERE {condition}"
        return execute_query(query, fetch=False)
    except mysql.connector.Error as e:
        print("Error executing delete query", e)
        return False

def empty_table(table_name):
    try:
        execute_query("SET FOREIGN_KEY_CHECKS = 0;", fetch=False)
        execute_query(f"TRUNCATE TABLE {table_name};", fetch=False)
        execute_query("SET FOREIGN_KEY_CHECKS = 1;", fetch=False)
        print(f"Table '{table_name}' has been successfully emptied.")
        return True
    except Exception as e:
        print(f"Error emptying table '{table_name}'", e)
        return False

def create_table(table_name, columns):
    try:
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})"
        if execute_query(query, fetch=False):
            print(f"Table '{table_name}' created successfully.")
            return True
    except Exception as e:
        print(f"Error creating table '{table_name}'", e)
        return False

def drop_table(table_name):
    try:
        query = f"DROP TABLE IF EXISTS {table_name}"
        if execute_query(query, fetch=False):
            print(f"Table '{table_name}' dropped successfully.")
            return True
    except Exception as e:
        print(f"Error dropping table '{table_name}'", e)
        return False
