# database_operations.py

import mysql.connector
from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE

def test_database_connection():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_DATABASE)

        if conn.is_connected():
            print("Connection to database is successful.")
            return True
        else:
            print("Failed to connect to the database.")
            return False
        
    except mysql.connector.Error as err:
        print(f"Error connecting to the MySQL database: {err}")
        return None

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

def retrieve_data(conn, apk_name):
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            # placeholder
            cursor.execute("SELECT * FROM analysis_results WHERE apk_name = %s", (apk_name,))
            data = cursor.fetchone()
            cursor.close()
            return data
        else:
            print("Database connection is not available.")
            return None
    except mysql.connector.Error as err:
        print(f"Error retrieving data from the MySQL database: {err}")
        return None

def close_database_connection(conn):
    if conn.is_connected():
        conn.close()

def create_apk_record(conn, filename, filesize, md5, sha1, sha256):
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            sql = "INSERT INTO apk_samples (file_name, file_size, md5, sha1, sha256) VALUES (%s, %s, %s, %s, %s)"
            val = (filename, filesize, md5, sha1, sha256)
            cursor.execute(sql, val)
            conn.commit()
            cursor.close()
            return True
        else:
            print("Database connection is not available.")
            return False
    except mysql.connector.Error as err:
        print(f"Error storing analysis result in the MySQL database: {err}")
        return False

def format_disk_usage(disk_usage):
    """ Format and display disk usage data in a table format. """
    if not disk_usage:
        print("No disk usage data available.")
        return

    # Determine the maximum length of database names for formatting
    max_db_name_length = max(len(str(usage[0])) for usage in disk_usage)

    # Print table header
    print(f"{'Database'.ljust(max_db_name_length)} | {'Size in MB'.rjust(10)}")
    print("-" * (max_db_name_length + 13))  # Adjust the total length as needed

    # Print each row of the table
    for usage in disk_usage:
        db_name, size_mb = usage
        print(f"{db_name.ljust(max_db_name_length)} | {str(size_mb).rjust(10)}")

def database_health_check():
    """ Check the overall health of the database. """
    try:
        with connect_to_database() as conn:
            if conn:
                with conn.cursor() as cursor:
                    print("\nDatabase Health Check Report")
                    print("="*30)

                    # Display database information
                    display_database_info(cursor)

                    # Checking for critical tables
                    critical_tables = ['users', 'apk_samples', 'android_permissions']
                    print("\nCritical Tables Check:")
                    for table in critical_tables:
                        cursor.execute(f"SHOW TABLES LIKE '{table}';")
                        result = cursor.fetchone()
                        status = "Exists" if result else "Missing"
                        print(f"  - {table.ljust(20)}: {status}")

                    # Query Performance Metrics
                    cursor.execute("SHOW STATUS LIKE 'Queries';")
                    query_count = cursor.fetchone()
                    print("\nPerformance Metrics:")
                    print(f"  - Queries executed: {query_count[1]}")

                    # Disk Space Usage
                    sql = """
                    SELECT table_schema 'Database', 
                           ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 'Size in MB'
                    FROM information_schema.TABLES 
                    WHERE table_schema = 'droidsecanalytica' 
                    GROUP BY table_schema;
                    """
                    cursor.execute(sql)
                    disk_usage = cursor.fetchall()
                    print("\nDisk Space Usage (MB):")
                    format_disk_usage(disk_usage)

                    return True
            else:
                print("Failed to establish a database connection.")
                return False
    except Exception as e:
        print(f"Database health check failed: {e}")
        return False


def list_tables(conn):
    """ List all tables in the database. """
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES;")
            tables = cursor.fetchall()
            print("Tables in the database:")
            for i in tables:
                print(" ", i[0])
            cursor.close()
            return True
        
        else:
            print("Database connection is not available.")
            return False
        
    except mysql.connector.Error as err:
        print(f"Error listing tables: {err}")
        return None

def check_table_exists(conn, table_name):
    """ Check if a specific table exists in the database. """
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = cursor.fetchone()
            cursor.close()
            return bool(result)
        else:
            print("Database connection is not available.")
            return False
    except mysql.connector.Error as err:
        print(f"Error checking table existence: {err}")
        return False

def get_table_schema(conn, table_name):
    """ Get the schema of a specific table. """
    try:
        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute(f"DESCRIBE {table_name};")
            schema = cursor.fetchall()
            print(f"Schema of {table_name}:", schema)
            cursor.close()
            return schema
        else:
            print("Database connection is not available.")
            return None
    except mysql.connector.Error as err:
        print(f"Error retrieving table schema: {err}")
        return None
    
def format_seconds_to_dhms(seconds):
    """ Format seconds into days, hours, minutes, and seconds. """
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def display_database_info(cursor):
    """ Display database information in a structured format. """
    print("\nDatabase Status:")

    # Checking database version
    cursor.execute("SELECT VERSION();")
    version = cursor.fetchone()
    print(f"  - Version: {version[0]}")

    # Server Uptime
    cursor.execute("SHOW STATUS LIKE 'Uptime';")
    uptime = cursor.fetchone()
    formatted_uptime = format_seconds_to_dhms(int(uptime[1]))
    print(f"  - Server Uptime: {formatted_uptime}")

    # Number of active connections
    cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
    connections = cursor.fetchone()
    print(f"  - Active Connections: {connections[1]}")

    # Database Size (example for MySQL, adjust for other DBMS)
    cursor.execute("SELECT table_schema 'Database', SUM(data_length + index_length) / 1024 / 1024 'Size in MB' FROM information_schema.TABLES WHERE table_schema = 'your_database_name' GROUP BY table_schema;")
    db_size = cursor.fetchone()
    if db_size:
        print(f"  - Database Size: {db_size[1]:.2f} MB")
