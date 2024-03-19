# db_utils.py

import mysql.connector
from utils import logging_utils
from . import db_conn, db_config

def disk_usage(min_size_mb: float = 0.0):
    try:
        query = """
        SELECT table_name AS 'Table',
            ROUND(SUM(data_length) / 1024 / 1024, 2) AS 'Data Size in MB',
            ROUND(SUM(index_length) / 1024 / 1024, 2) AS 'Index Size in MB',
            ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Total Size in MB'
        FROM information_schema.TABLES
        WHERE table_schema = '{}'
        GROUP BY table_name
        HAVING 'Total Size in MB' >= {}
        ORDER BY 'Total Size in MB' DESC;
        """.format(db_config.DB_DATABASE, min_size_mb)
        return db_conn.execute_query(query, fetch=True)
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching disk usage", e)
        return []

# Database summary
def database_summary():
    try:
        with db_conn.database_connection() as conn:
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

# Thread information
def thread_summary():
    try:
        sql = "SELECT VARIABLE_NAME AS 'Metric', VARIABLE_VALUE AS 'Value' "
        sql += "FROM information_schema.GLOBAL_STATUS "
        sql += "WHERE VARIABLE_NAME IN ('Threads_connected', 'Threads_running', 'Threads_cached', 'Threads_created', 'Threads_waiting');"
        thread_info = db_conn.execute_query(sql, fetch=True)
        return thread_info
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching thread information", e)
        return []

# Query statistics
def get_query_statistics():
    try:
        sql = "SHOW STATUS LIKE 'Queries';"
        return db_conn.execute_query(sql, fetch=True)
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching query statistics", e)
        return []
    
# Get database table info
def tables_summary():
    try:
        result = db_conn.execute_query("SHOW TABLES;", fetch=True)
        table_info = []
        for (table_name,) in result:
            num_columns = len(db_conn.execute_query(f"SHOW COLUMNS FROM {table_name};", fetch=True))
            num_rows = db_conn.execute_query(f"SELECT COUNT(*) FROM {table_name};", fetch=True)[0][0]

            # Calculate the size in MB for the table
            size_query = f"""
            SELECT table_schema 'Database', ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 'Size in MB'
            FROM information_schema.TABLES
            WHERE table_schema = '{db_config.DB_DATABASE}' AND table_name = '{table_name}'
            GROUP BY table_schema, table_name;
            """
            size_result = db_conn.execute_query(size_query, fetch=True)
            size_mb = size_result[0][1] if size_result else 0.0

            table_info.append((table_name, num_columns, num_rows, size_mb))
        return table_info
    except mysql.connector.Error as e:
        logging_utils.log_error("Error listing tables", e)
        return []
