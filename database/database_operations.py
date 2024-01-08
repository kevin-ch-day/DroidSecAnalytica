# database_main.py

import mysql.connector
from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

def test_database_connection():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE
        )
        if conn.is_connected():
            print(f"Connection to MySQL database is successful.")
            return True
        else:
            print(f"Failed to connect to the MySQL database.")
            return False
    except mysql.connector.Error as err:
        print(f"Error connecting to the MySQL database: {err}")
        return None

# Function to connect to the MySQL database
def connect_to_database():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Error connecting to the MySQL database: {err}")
        return None

# Function to store analysis results in the MySQL database
def store_analysis_result(conn, result_data):
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            # Define your SQL INSERT statement here based on your database schema
            # Example: cursor.execute("INSERT INTO analysis_results (apk_name, analysis_type, result) VALUES (%s, %s, %s)", (result_data["apk_name"], result_data["analysis_type"], result_data["result"]))
            conn.commit()
            return True
        else:
            print("Database connection is not available.")
            return False
    except mysql.connector.Error as err:
        print(f"Error storing analysis result in the MySQL database: {err}")
        return False

# Function to retrieve data from the MySQL database
def retrieve_data(conn, apk_name):
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            # Define your SQL SELECT statement here based on your database schema
            # Example: cursor.execute("SELECT * FROM analysis_results WHERE apk_name = %s", (apk_name,))
            data = cursor.fetchone()  # Adjust this based on your data retrieval needs
            return data
        else:
            print("Database connection is not available.")
            return None
    except mysql.connector.Error as err:
        print(f"Error retrieving data from the MySQL database: {err}")
        return None

# Close the database connection when done
def close_database_connection(conn):
    if conn.is_connected():
        conn.close()

def save_malware_record(conn, filename, filesize, md5, sha1, sha256):
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            sql = "insert into malware_samples (file_name, file_size, md5, sha1, sha256) "
            sql = sql + "values (%s, %d, %s, %s, %s)"
            val = ("{filename}", "{filesize}", "{md5}", "{sha1}", "{sha256}")
            cursor.execute(sql, val)
            conn.commit()
            return True
        
        else:
            print("Database connection is not available.")
            return False
    
    except mysql.connector.Error as err:
        print(f"Error storing analysis result in the MySQL database: {err}")
        return False