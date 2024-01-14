import mysql.connector
import logging
import database.DBConnectionManager as DBConnectionManager

def test_database_connection():
    DBConnectionManager.test_connection()

def check_for_table(table_name):
    try:
        conn = DBConnectionManager.connect_to_database()
        if conn:
            result = DBConnectionManager.execute_sql(conn, f"SELECT 1 FROM {table_name} LIMIT 1", fetch=True)
            return bool(result)
    except mysql.connector.Error as e:
        if e.errno == mysql.connector.errorcode.ER_NO_SUCH_TABLE:
            logging.info(f"Table '{table_name}' does not exist.")
        else:
            logging.error(f"Error checking for table '{table_name}': {e}")
    finally:
        if conn:
            DBConnectionManager.close_database_connection(conn)
    return False

def create_apk_record(conn, filename, filesize, md5, sha1, sha256):
    sql = "INSERT INTO apk_samples (file_name, file_size, md5, sha1, sha256) VALUES (%s, %s, %s, %s, %s)"
    val = (filename, filesize, md5, sha1, sha256)
    return DBConnectionManager.execute_sql(conn, sql, val)

def database_health_check():
    try:
        conn = DBConnectionManager.connect_to_database()
        if conn and conn.is_connected():
            cursor = conn.cursor()
            print("\nDatabase Health Check Report")
            print("=" * 30)

            # Assuming display_database_info is defined elsewhere
            display_database_info(cursor)

            critical_tables = ['users', 'apk_samples', 'android_permissions']
            print("\nCritical Tables Check:")
            for table in critical_tables:
                cursor.execute(f"SHOW TABLES LIKE '{table}';")
                result = cursor.fetchone()
                status = "Exists" if result else "Missing"
                print(f"  - {table.ljust(20)}: {status}")

            cursor.execute("SHOW STATUS LIKE 'Queries';")
            query_count = cursor.fetchone()
            print("\nPerformance Metrics:")
            print(f"  - Queries executed: {query_count[1]}")

            sql = """
            SELECT table_schema 'Database', 
                   ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 'Size in MB'
            FROM information_schema.TABLES 
            WHERE table_schema != 'information_schema'
            GROUP BY table_schema;
            """
            cursor.execute(sql)
            disk_usage = cursor.fetchall()
            print("\nDisk Space Usage (MB):")
            # Assuming format_disk_usage is defined elsewhere
            format_disk_usage(disk_usage)
            cursor.close()
            DBConnectionManager.close_database_connection(conn)
        else:
            print("Failed to establish a database connection.")
            return False
    except Exception as e:
        print(f"Database health check failed: {e}")
        return False
    
def format_disk_usage(disk_usage):
    if not disk_usage:
        print("No disk usage data available.")
        return

    max_db_name_length = max(len(str(usage[0])) for usage in disk_usage)
    print(f"{'Database'.ljust(max_db_name_length)} | {'Size in MB'.rjust(10)}")
    print("-" * (max_db_name_length + 13))
    for usage in disk_usage:
        db_name, size_mb = usage
        print(f"{db_name.ljust(max_db_name_length)} | {str(size_mb).rjust(10)}")


def display_database_info(cursor):
    print("\nDatabase Status:")
    
    cursor.execute("SELECT VERSION();")
    version = cursor.fetchone()
    print(f" - Version: {version[0]}")
    
    cursor.execute("SHOW STATUS LIKE 'Uptime';")
    uptime = cursor.fetchone()
    formatted_uptime = format_seconds_to_dhms(int(uptime[1]))
    print(f"  - Server Uptime: {formatted_uptime}")
    
    cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
    connections = cursor.fetchone()
    print(f"  - Active Connections: {connections[1]}")
    
    cursor.execute("""
    SELECT table_schema 'Database', 
        SUM(data_length + index_length) / 1024 / 1024 'Size in MB' 
    FROM information_schema.TABLES 
    GROUP BY table_schema
    """)
    db_size = cursor.fetchall()
    for db in db_size:
        print(f"  - {db[0]} Database Size: {db[1]:.2f} MB")

def format_seconds_to_dhms(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def check_android_malware_hash_table_exists():
    try:
        conn = DBConnectionManager.connect_to_database()
        if conn:
            result = DBConnectionManager.check_for_table(conn, 'android_malware_hashes')
            return result
        return False
    except Exception as e:
        print(f"An error occurred while checking for the table: {e}")
        return False
    finally:
        if conn:
            DBConnectionManager.close_database_connection(conn)

def create_android_malware_hash_table():
    try:
        # Establish a connection to the database
        conn = DBConnectionManager.connect_to_database()
        if conn:
            # SQL statement to create the android_malware_hashes table
            sql_create_table = '''
                CREATE TABLE android_malware_hashes (
                    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    malware_category VARCHAR(255) DEFAULT NULL,
                    md5 VARCHAR(250) DEFAULT NULL,
                    sha1 VARCHAR(250) DEFAULT NULL,
                    sha256 VARCHAR(250) DEFAULT NULL,
                    location VARCHAR(100) DEFAULT NULL,
                    month VARCHAR(100) DEFAULT NULL)
            '''
            if DBConnectionManager.execute_sql(conn, sql_create_table):
                return True
            else:
                print("Error executing the SQL statement")
                return False
            
        print("Unable to establish a database connection")
        return False
    
    except Exception as e:
       print(f"An error occurred while creating the table: {e}")
       return False
    finally:
        if conn:
            DBConnectionManager.close_database_connection(conn)

def list_tables():
    # Lists all tables in the database along with their number of columns and rows.
    try:
        conn = DBConnectionManager.connect_to_database()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES;")
            tables = cursor.fetchall()

            table_info = []
            for (table_name,) in tables:
                # Count the number of columns
                cursor.execute(f"SHOW COLUMNS FROM {table_name};")
                num_columns = len(cursor.fetchall())

                # Count the number of rows
                cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
                num_rows = cursor.fetchone()[0]

                table_info.append((table_name, num_columns, num_rows))

            cursor.close()
            return table_info

        else:
            print("Unable to establish a database connection.")
            return None

    except Exception as e:
        print(f"An error occurred while listing the tables: {e}")
        return None

    finally:
        if conn:
            DBConnectionManager.close_database_connection(conn)

def display_tables_info():
    # Fetches and displays information about all tables in the database.
    results = list_tables()
    if results:
        max_name_length = max(len(table_name) for table_name, _, _ in results)
        name_column_width = max(max_name_length, len('Table Name'))

        # Header
        print(f"\033[1m{'Table Name'.ljust(name_column_width)} | {'# Columns'.rjust(10)} | {'# Rows'.rjust(10)}\033[0m")
        print("=" * (name_column_width + 27))  # Table border

        # Data rows
        for table_name, num_columns, num_rows in results:
            formatted_columns = f"{num_columns:,}"
            formatted_rows = f"{num_rows:,}"
            print(f"{table_name.ljust(name_column_width)} | {formatted_columns.rjust(10)} | {formatted_rows.rjust(10)}")
    else:
        print("No table information available or failed to retrieve table information.")

def empty_table(table_name):
    conn = None
    try:
        conn = DBConnectionManager.connect_to_database()
        if conn:
            if DBConnectionManager.truncate_table(conn, table_name):
                logging.info(f"Table '{table_name}' emptied successfully.")
                return True
            else:
                logging.error(f"Error emptying table '{table_name}'.")
                return False
        else:
            logging.error("Failed to establish a database connection.")
            return False
    except Exception as e:
        logging.error(f"An error occurred while emptying the table '{table_name}': {e}")
        return False
    finally:
        if conn:
            DBConnectionManager.close_database_connection(conn)