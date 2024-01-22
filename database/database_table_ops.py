# database_table_ops.py

import logging
import mysql.connector
from database_query_executor import execute_query

def create_table(table_name, columns):
    try:
        column_definitions = ', '.join(columns)
        sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({column_definitions})"
        if execute_query(sql):
            logging.info(f"Table '{table_name}' created successfully.")
            return True
        else:
            logging.error(f"Failed to create table '{table_name}'.")
            return False
    except mysql.connector.Error as e:
        logging.error(f"Error creating table '{table_name}': {e}")
        return False

def check_for_table(table_name):
    try:
        sql = "SHOW TABLES LIKE %s;"
        result = execute_query(sql, (table_name,), fetchone=True)
        return bool(result)
    except mysql.connector.Error as e:
        logging.error(f"Error checking for table '{table_name}': {e}")
        return False

def truncate_table(table_name):
    try:
        sql = f"TRUNCATE TABLE {table_name}"
        if execute_query(sql):
            logging.info(f"Table '{table_name}' truncated successfully.")
            return True
        else:
            logging.error(f"Failed to truncate table '{table_name}'.")
            return False
    except mysql.connector.Error as e:
        logging.error(f"Error truncating table '{table_name}': {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error while truncating table '{table_name}': {e}")
        return False

def drop_table(table_name):
    try:
        sql = f"DROP TABLE IF EXISTS {table_name}"
        if execute_query(sql):
            logging.info(f"Table '{table_name}' dropped successfully.")
            return True
        else:
            logging.error(f"Failed to drop table '{table_name}'.")
            return False
    except mysql.connector.Error as e:
        logging.error(f"Error dropping table '{table_name}': {e}")
        return False

def add_column(table_name, column_definition):
    try:
        sql = f"ALTER TABLE {table_name} ADD {column_definition}"
        if execute_query(sql):
            logging.info(f"Column added to '{table_name}' successfully.")
            return True
        else:
            logging.error(f"Failed to add column to table '{table_name}'.")
            return False
    except mysql.connector.Error as e:
        logging.error(f"Error adding column to table '{table_name}': {e}")
        return False

def remove_column(table_name, column_name):
    try:
        sql = f"ALTER TABLE {table_name} DROP COLUMN {column_name}"
        if execute_query(sql):
            logging.info(f"Column '{column_name}' removed from '{table_name}' successfully.")
            return True
        else:
            logging.error(f"Failed to remove column '{column_name}' from table '{table_name}'.")
            return False
    except mysql.connector.Error as e:
        logging.error(f"Error removing column '{column_name}' from table '{table_name}': {e}")
        return False