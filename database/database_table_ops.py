# database_table_ops.py

from database_query_executor import execute_query
import logging

def create_table(table_name, columns):
    column_definitions = ', '.join(columns)
    sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({column_definitions})"
    return execute_query(sql)

def check_for_table(table_name):
    sql = "SHOW TABLES LIKE %s;"
    result = execute_query(sql, (table_name,), fetchone=True)
    return bool(result)

def truncate_table(table_name):
    sql = f"TRUNCATE TABLE {table_name}"
    return execute_query(sql)

def drop_table(table_name):
    sql = f"DROP TABLE IF EXISTS {table_name}"
    return execute_query(sql)

def add_column(table_name, column_definition):
    sql = f"ALTER TABLE {table_name} ADD {column_definition}"
    return execute_query(sql)

def remove_column(table_name, column_name):
    sql = f"ALTER TABLE {table_name} DROP COLUMN {column_name}"
    return execute_query(sql)
