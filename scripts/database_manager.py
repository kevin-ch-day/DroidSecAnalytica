import mysql.connector
import logging
from mysql.connector import errorcode

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database credentials
DB_HOST = "localhost"
DB_USER = "dbadmin"
DB_PASSWORD = "Password01"
DB_DATABASE = "droidsecanalytica"

def connect_to_database(retry_count=3):
    attempt = 0
    while attempt < retry_count:
        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_DATABASE
            )
            return conn
        except mysql.connector.Error as error:
            logging.error(f"Attempt {attempt+1} failed: Error connecting to database: {error}")
            attempt += 1
    return None

def close_database_connection(connection):
    try:
        if connection:
            connection.close()
    except mysql.connector.Error as error:
        logging.error(f"close_database_connection: Error closing database connection: {error}")

def execute_sql_statement(cursor, sql, data=None):
    logging.info(f'Executing SQL statement: {sql}, Data: {data}')
    try:
        with cursor.connection:
            cursor.execute(sql, data if data else ())
    except mysql.connector.Error as error:
        logging.error(f"Error executing SQL statement '{sql}': {error}")
        return False
    return True

def execute_sql_query(cursor, sql):
    try:
        cursor.execute(sql)
        return cursor.fetchall()
    except mysql.connector.Error as error:
        logging.error(f"Error executing SQL query '{sql}': {error}")
        return []
    except AttributeError as error:
        logging.error(f"Cursor is invalid or closed: {error}")
        return []

def create_table(cursor, table_name, columns):
    logging.info(f'Creating table {table_name} with columns {columns}')
    try:
        with cursor.connection:
            cursor.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(columns)})")
    except mysql.connector.Error as error:
        logging.error(f"Error creating table '{table_name}': {error}")
        return False
    return True

def truncate_table(cursor, table_name):
    try:
        with cursor.connection:
            cursor.execute(f"TRUNCATE TABLE {table_name}")
    except mysql.connector.Error as error:
        logging.error(f"Error truncating table '{table_name}': {error}")
        return False
    return True

def drop_table(cursor, table_name):
    try:
        with cursor.connection:
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
    except mysql.connector.Error as error:
        logging.error(f"Error dropping table '{table_name}': {error}")
        return False
    return True

def check_for_table(cursor, table_name):
    try:
        cursor.execute(f"SELECT 1 FROM {table_name} LIMIT 1")
        return True
    except mysql.connector.Error as e:
        if e.errno == errorcode.ER_NO_SUCH_TABLE:
            logging.info(f"Table '{table_name}' does not exist.")
            return False
        else:
            logging.error(f"Error checking for table '{table_name}': {e}")
            return False

def truncate_table(table_name):
    conn = connect_to_database()
    cursor = conn.cursor()
    sql = f'TRUNCATE TABLE {table_name}'
    execute_sql_query(cursor, sql)
    print(f"{table_name} table cleared.")
    close_database_connection(conn)