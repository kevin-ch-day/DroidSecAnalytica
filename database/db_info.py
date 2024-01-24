import mysql.connector

from utils import logging_utils
from . import db_manager
from database.db_config import DB_DATABASE

# Get disk usage  
def get_disk_usage(min_size_mb: float = 0.0):
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
        """.format(DB_DATABASE, min_size_mb)
        return db_manager.execute_query(query, fetch=True)
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching disk usage", e)
        return []

# Get database information
def get_database_info():
    try:
        with db_manager.database_connection() as conn:
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
def get_thread_information():
    try:
        sql = "SELECT VARIABLE_NAME AS 'Metric', VARIABLE_VALUE AS 'Value' "
        sql += "FROM information_schema.GLOBAL_STATUS "
        sql += "WHERE VARIABLE_NAME IN ('Threads_connected', 'Threads_running', 'Threads_cached', 'Threads_created', 'Threads_waiting');"
        thread_info = db_manager.execute_query(sql, fetch=True)
        return thread_info
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching thread information", e)
        return []

# Query statistics
def get_query_statistics():
    try:
        sql = "SHOW STATUS LIKE 'Queries';"
        return db_manager.execute_query(sql, fetch=True)
    except mysql.connector.Error as e:
        logging_utils.log_error("Error fetching query statistics", e)
        return []