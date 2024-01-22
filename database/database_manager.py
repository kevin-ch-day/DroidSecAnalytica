import mysql.connector
import logging
from contextlib import contextmanager
from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

# Configure logging only if not already configured by other modules
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@contextmanager
def database_connection():
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

def execute_query(sql, values=None, fetch_mode=None):
    try:
        with database_connection() as conn:
            if conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql, values or ())
                    if fetch_mode == 'all':
                        return cursor.fetchall()
                    elif fetch_mode == 'one':
                        return cursor.fetchone()
                    conn.commit()
            else:
                logging.error("Failed to establish a database connection.")
                return None
    except mysql.connector.Error as error:
        logging.error(f"Error executing SQL query: {error}")
        return None

def test_connection():
    with database_connection() as conn:
        if conn:
            logging.info("Connection to database is successful.")
            return True
        else:
            logging.error("Failed to connect to the database.")
            return False

def truncate_all_tables():
    with database_connection() as conn:
        if conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SHOW TABLES;")
                    tables = cursor.fetchall()
                    for (table_name,) in tables:
                        logging.info(f"Truncating table '{table_name}'")
                        if not execute_query(f"TRUNCATE TABLE {table_name}"):
                            logging.error(f"Failed to truncate table '{table_name}'")
                            return False
                return True
            except mysql.connector.Error as error:
                logging.error(f"Error during truncation: {error}")
                return False
        else:
            logging.error("Failed to establish a database connection.")
            return False
