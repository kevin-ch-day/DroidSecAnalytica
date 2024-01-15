# database_manager.py

import mysql.connector
import logging

from database.DBConfig import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def connect_to_database():
    """Establish a database connection."""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE
        )
        return conn
    except mysql.connector.Error as error:
        logging.error(f"Error connecting to database: {error}")
        return None

def close_database_connection(connection):
    """Close the database connection."""
    try:
        if connection and connection.is_connected():
            connection.close()
    except mysql.connector.Error as error:
        logging.error(f"Error closing database connection: {error}")

def execute_sql(conn, sql, data=None, fetch=False):
    try:
        cursor = conn.cursor()
        cursor.execute(sql, data or ())
        if fetch:
            return cursor.fetchall()
        conn.commit()
        return True
    
    except mysql.connector.Error as error:
        print(f"Error executing SQL statement '{sql}': {error}")
        return False if fetch else None  # Return False or None based on query type
    finally:
        cursor.close()

def create_table(conn, table_name, columns):
    """Create a table in the database."""
    sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(columns)})"
    return execute_sql(conn, sql)

def truncate_table(conn, table_name):
    """Truncate a table in the database."""
    sql = f"TRUNCATE TABLE {table_name}"
    return execute_sql(conn, sql)

def drop_table(conn, table_name):
    """Drop a table from the database."""
    sql = f"DROP TABLE IF EXISTS {table_name}"
    return execute_sql(conn, sql)

def test_connection():
    """Test the database connection."""
    try:
        conn = connect_to_database()
        if conn and conn.is_connected():
            print("Connection to database is successful.")
            close_database_connection(conn)
            return True
        else:
            print("Failed to connect to the database.")
            return False
    except mysql.connector.Error as err:
        print(f"Error connecting to the MySQL database: {err}")
        return False
    
def truncate_all_tables():
    # Truncates all tables in the database.
    try:
        conn = connect_to_database()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES;")
            tables = cursor.fetchall()
            tables_to_skip = None

            for (table_name,) in tables:
                logging.info(f"Truncating table '{table_name}'")
                if not truncate_table(conn, table_name):
                    logging.error(f"Failed to truncate table '{table_name}'")
                    return False

            return True
        else:
            logging.error("Failed to establish a database connection.")
            return False

    except mysql.connector.Error as error:
        logging.error(f"Error while truncating tables: {error}")
        return False

    finally:
        if conn:
            close_database_connection(conn)