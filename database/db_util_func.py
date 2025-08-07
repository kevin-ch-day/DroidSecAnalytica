# db_util_func.py

from typing import Optional
import mysql.connector

from utils import logging_utils

logger = logging_utils.get_logger(__name__)

from . import db_conn, db_config

def execute_query(query, params=None, fetch=False):
    try:
        return db_conn.execute_query(query, params=params, fetch=fetch)
    except mysql.connector.Error:
        logger.exception("Database query failed")
        return []

def get_table_row_count(table_name: str) -> Optional[int]:
    try:
        sql = f"SELECT COUNT(*) FROM {table_name}"
        result = execute_query(sql)
        if result:
            # Access the first item of the first row
            return result[0][0]
        else:
            return 0
    except Exception as e:
        print(f"[ERROR] Failed to retrieve row count for table {table_name}: {e}")
        return None

def check_column_value_by_id(table, column_name, record_id):
    # Checks if a specific column for a given record ID has a value.
    sql = f"SELECT {column_name} FROM {table} WHERE id = %s;"
    params = (record_id,)

    try:
        result = db_conn.execute_query(sql, params=params, fetch=True)
        if result and result[0][0] is not None and result[0][0] != '':
            return True
        else:
            return False
    except Exception as e:
        print(f"Failed to check column value for {column_name}: {e}")
        return False

def update_column_value_by_id(table, column_name, value, record_id):
    # Updates the value of a specific column for a given record ID.
    sql = f"UPDATE {table} SET {column_name} = %s WHERE id = %s;"
    params = (value, record_id)

    try:
        db_conn.execute_query(sql, params=params, fetch=False)
        print(f"Successfully updated {column_name} for record ID {record_id}.")
    except Exception as e:
        print(f"Failed to update {column_name} for record ID {record_id}: {e}")

def check_vt_malware_size(id):
    return check_column_value_by_id("malware_samples", "sample_size", id)

def check_vt_malware_formatted_size(id):
    return check_column_value_by_id("malware_samples", "formatted_sample_size", id)

def check_vt_malware_url(id):
    return check_column_value_by_id("malware_samples", "virustotal_url", id)

def update_sample_size(id, new_value):
    update_column_value_by_id("malware_samples", "sample_size", new_value, id)

def update_formatted_size_sample(id, new_value):
    update_column_value_by_id("malware_samples", "formatted_sample_size", new_value, id)

def update_virustotal_url(id, new_value):
    update_column_value_by_id("malware_samples", "virustotal_url", new_value, id)

def disk_usage_report(min_size_mb: float = 0.0):
    """
    Retrieves and displays disk usage information for all tables in the database.
    Filters tables by minimum size if specified. Provides a summary of total storage.
    """
    query = """
    SELECT table_name AS 'Table',
        ROUND(SUM(data_length) / 1024 / 1024, 2) AS 'Data Size in MB',
        ROUND(SUM(index_length) / 1024 / 1024, 2) AS 'Index Size in MB',
        ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Total Size in MB'
    FROM information_schema.TABLES
    WHERE table_schema = %s
    GROUP BY table_name
    HAVING `Total Size in MB` >= %s
    ORDER BY `Total Size in MB` DESC;
    """
    
    try:
        # Fetch disk usage data
        disk_usage = execute_query(query, params=(db_config.DB_DATABASE, min_size_mb), fetch=True)

        if not disk_usage:
            print("\n[INFO] No disk usage data available.")
            return
        
        # Compute total database usage
        total_data_size = sum(row[1] for row in disk_usage)
        total_index_size = sum(row[2] for row in disk_usage)
        total_db_size = sum(row[3] for row in disk_usage)

        # Identify the largest table (if available)
        largest_table = max(disk_usage, key=lambda x: x[3]) if disk_usage else None

        # Display summary
        print("\n" + "=" * 60)
        print(f" DATABASE DISK USAGE SUMMARY ({db_config.DB_DATABASE})")
        print("=" * 60)
        print(f" Total Tables: {len(disk_usage)}")
        print(f" Largest Table: {largest_table[0]} ({largest_table[3]} MB)" if largest_table else " Largest Table: None")
        print(f" Total Data Size: {total_data_size:.2f} MB")
        print(f" Total Index Size: {total_index_size:.2f} MB")
        print(f" Total Database Size: {total_db_size:.2f} MB")
        print("=" * 60)

        # Determine the longest table name for dynamic column sizing
        max_table_name_length = max(len(row[0]) for row in disk_usage)
        col_widths = [max(35, max_table_name_length), 15, 15, 15]

        # Display Table Headers with Dynamic Column Width
        header = f"{'Table':<{col_widths[0]}} | {'Data Size (MB)':>{col_widths[1]}} | {'Index Size (MB)':>{col_widths[2]}} | {'Total Size (MB)':>{col_widths[3]}}"
        print("\nDisk Usage Details:")
        print("-" * len(header))
        print(header)
        print("-" * len(header))

        # Display Data Rows
        for table, data_size, index_size, total_size in disk_usage:
            print(f"{table:<{col_widths[0]}} | {data_size:>{col_widths[1]}.2f} | {index_size:>{col_widths[2]}.2f} | {total_size:>{col_widths[3]}.2f}")

        # Footer
        print("-" * len(header))

    except Exception:
        logger.exception("Error retrieving and displaying disk usage")
