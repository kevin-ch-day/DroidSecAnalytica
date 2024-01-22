# database_manager.py

import mysql.connector
import logging
from contextlib import contextmanager

# Database configuration variables
from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@contextmanager
def database_connection():
    """Context manager for database connection."""
    conn = None
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE
        )
        yield conn
    except mysql.connector.Error as error:
        logging.error(f"Error in database operation: {error}")
        yield None
    finally:
        if conn and conn.is_connected():
            conn.close()
            logging.info("Database connection closed.")

def execute_sql(sql, data=None, fetch=False):
    """Execute an SQL statement."""
    with database_connection() as conn:
        if conn is None:
            return False if fetch else None
        try:
            cursor = conn.cursor()
            cursor.execute(sql, data or ())
            if fetch:
                return cursor.fetchall()
            conn.commit()
            return True
        except mysql.connector.Error as error:
            logging.error(f"Error executing SQL statement '{sql}': {error}")
            return False if fetch else None
        finally:
            cursor.close()

def test_connection():
    """Test the database connection."""
    with database_connection() as conn:
        if conn:
            logging.info("Connection to database is successful.")
            return True
        else:
            logging.error("Failed to connect to the database.")
            return False

def truncate_all_tables():
    """Truncates all tables in the database."""
    with database_connection() as conn:
        if conn:
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES;")
            tables = cursor.fetchall()
            for (table_name,) in tables:
                logging.info(f"Truncating table '{table_name}'")
                if not execute_sql(f"TRUNCATE TABLE {table_name}"):
                    logging.error(f"Failed to truncate table '{table_name}'")
                    return False
            return True
        else:
            logging.error("Failed to establish a database connection.")
            return False
