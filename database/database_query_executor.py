# database_query_executor.py

from . import database_connection
import logging
import mysql.connector

def execute_query(sql, values=None, fetch=False, fetchone=False):
    with database_connection() as conn:
        if conn is None:
            return None
        try:
            cursor = conn.cursor()
            cursor.execute(sql, values or ())
            if fetch:
                return cursor.fetchall()
            if fetchone:
                return cursor.fetchone()
            conn.commit()
        except mysql.connector.Error as error:
            logging.error(f"Error executing SQL query: {error}")
            return None
        finally:
            if cursor:
                cursor.close()

def check_for_table(table_name):
    sql = "SHOW TABLES LIKE %s;"
    result = execute_query(sql, (table_name,), fetchone=True)
    return bool(result)

def insert_data(table_name, data):
    placeholders = ', '.join(['%s'] * len(data))
    sql = f"INSERT INTO {table_name} VALUES ({placeholders})"
    return execute_query(sql, data)

def update_data(table_name, data, conditions):
    set_clause = ', '.join([f"{key} = %s" for key in data])
    condition_clause = ' AND '.join([f"{key} = %s" for key in conditions])
    sql = f"UPDATE {table_name} SET {set_clause} WHERE {condition_clause}"
    values = list(data.values()) + list(conditions.values())
    return execute_query(sql, values)

def delete_data(table_name, conditions):
    condition_clause = ' AND '.join([f"{key} = %s" for key in conditions])
    sql = f"DELETE FROM {table_name} WHERE {condition_clause}"
    values = list(conditions.values())
    return execute_query(sql, values)

def select_data(table_name, columns, conditions=None):
    column_clause = ', '.join(columns)
    sql = f"SELECT {column_clause} FROM {table_name}"
    values = None
    if conditions:
        condition_clause = ' AND '.join([f"{key} = %s" for key in conditions])
        sql += f" WHERE {condition_clause}"
        values = list(conditions.values())
    return execute_query(sql, values, fetch=True)

def execute_batch(sql, values_list):
    with database_connection() as conn:
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
