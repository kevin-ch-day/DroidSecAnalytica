# database_manager.py

import mysql.connector
from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

def create_connection():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE
        )

        if conn.is_connected():
            print("Connected to the MySQL database")
            return conn

    except mysql.connector.Error as e:
        print("Error connecting to MySQL:", e)
    
    return None

def execute_query(conn, query, fetch=True):
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        if fetch:
            return cursor.fetchall()
        else:
            conn.commit()

    except mysql.connector.Error as e:
        print("Error executing query:", e)
        return None

def close_connection(conn):
    try:
        if conn is not None and conn.is_connected():
            conn.close()
            print("Connection to MySQL database is closed")
    except mysql.connector.Error as e:
        print("Error closing connection:", e)

def execute_insert(conn, table, data):
    try:
        cursor = conn.cursor()
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['%s'] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        cursor.execute(query, tuple(data.values()))
        conn.commit()
        print("Insertion successful")

    except mysql.connector.Error as e:
        print("Error executing insert query:", e)

def execute_update(conn, table, data, condition):
    try:
        cursor = conn.cursor()
        update_values = ', '.join([f"{key} = %s" for key in data.keys()])
        query = f"UPDATE {table} SET {update_values} WHERE {condition}"
        cursor.execute(query, tuple(data.values()))
        conn.commit()
        print("Update successful")

    except mysql.connector.Error as e:
        print("Error executing update query:", e)

def execute_delete(conn, table, condition):
    try:
        cursor = conn.cursor()
        query = f"DELETE FROM {table} WHERE {condition}"
        cursor.execute(query)
        conn.commit()
        print("Deletion successful")

    except mysql.connector.Error as e:
        print("Error executing delete query:", e)
