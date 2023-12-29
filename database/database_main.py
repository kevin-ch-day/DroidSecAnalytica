# database_main.py

import mysql.connector
from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

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

# Add more database-related functions as needed for your project

# Close the database connection when done
def close_database_connection(conn):
    if conn.is_connected():
        conn.close()

# Testing
if __name__ == "__main__":
    # Replace with your MySQL database connection details
    host = "your_mysql_host"
    user = "your_mysql_user"
    password = "your_mysql_password"
    database = "your_mysql_database"
    
    conn = connect_to_database(host, user, password, database)
    if conn:
        analysis_result = {"apk_name": "example.apk", "analysis_type": "static", "result": "success"}
        if store_analysis_result(conn, analysis_result):
            retrieved_data = retrieve_data(conn, "example.apk")
            if retrieved_data:
                print("Database operations executed successfully.")
            else:
                print("Error in database operations.")
        close_database_connection(conn)
    else:
        print("Error connecting to the MySQL database.")
