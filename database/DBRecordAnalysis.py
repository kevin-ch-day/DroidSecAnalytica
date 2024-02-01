# DBRecordAnalysis.py

from . import DBConnectionManager as dbConnect
from utils import logging_utils

# Executes a SQL query and returns the results or None if should_fetch is False
def execute_sql(query: str, params: tuple = None, should_fetch: bool = False):
    try:
        return dbConnect.execute_query(query, params, fetch=should_fetch)
    except Exception as e:
        logging_utils.log_error(f"Error executing query: {query}", e)
        return None if should_fetch else False