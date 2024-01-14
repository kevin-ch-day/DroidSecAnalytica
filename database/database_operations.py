import mysql.connector
import logging

from database.database_config import DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def connect_to_database(retry_count=3):
    for attempt in range(retry_count):
        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_DATABASE
            )
            return conn
        except mysql.connector.Error as error:
            logging.error(f"Attempt {attempt + 1} failed: Error connecting to database: {error}")
    return None

def close_database_connection(connection):
    try:
        if connection and connection.is_connected():
            connection.close()
    except mysql.connector.Error as error:
        logging.error(f"close_database_connection: Error closing database connection: {error}")

def execute_sql(cursor, sql, data=None):
    try:
        with cursor.connection:
            cursor.execute(sql, data if data else ())
    except mysql.connector.Error as error:
        logging.error(f"Error executing SQL statement '{sql}': {error}")
        return False
    return True

def create_table(cursor, table_name, columns):
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
        if e.errno == mysql.connector.errorcode.ER_NO_SUCH_TABLE:
            logging.info(f"Table '{table_name}' does not exist.")
            return False
        else:
            logging.error(f"Error checking for table '{table_name}': {e}")
            return False

def test_database_connection():
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

def retrieve_data(conn, apk_name):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analysis_results WHERE apk_name = %s", (apk_name,))
        data = cursor.fetchone()
        cursor.close()
        return data
    except mysql.connector.Error as err:
        print(f"Error retrieving data from the MySQL database: {err}")
        return None

def create_apk_record(conn, filename, filesize, md5, sha1, sha256):
    try:
        cursor = conn.cursor()
        sql = "INSERT INTO apk_samples (file_name, file_size, md5, sha1, sha256) VALUES (%s, %s, %s, %s, %s)"
        val = (filename, filesize, md5, sha1, sha256)
        cursor.execute(sql, val)
        conn.commit()
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print(f"Error storing analysis result in the MySQL database: {err}")
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

def database_health_check():
    try:
        conn = connect_to_database()
        if conn and conn.is_connected():
            with conn.cursor() as cursor:
                print("\nDatabase Health Check Report")
                print("=" * 30)
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
                WHERE table_schema = 'droidsecanalytica' 
                GROUP BY table_schema;
                """
                cursor.execute(sql)
                disk_usage = cursor.fetchall()
                print("\nDisk Space Usage (MB):")
                format_disk_usage(disk_usage)
                close_database_connection(conn)
                return True
        else:
            print("Failed to establish a database connection.")
            return False
    except Exception as e:
        print(f"Database health check failed: {e}")
        return False

def display_database_info(cursor):
    print("\nDatabase Status:")

    cursor.execute("SELECT VERSION();")
    version = cursor.fetchone()
    print(f"  - Version: {version[0]}")

    cursor.execute("SHOW STATUS LIKE 'Uptime';")
    uptime = cursor.fetchone()
    formatted_uptime = format_seconds_to_dhms(int(uptime[1]))
    print(f"  - Server Uptime: {formatted_uptime}")

    cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
    connections = cursor.fetchone()
    print(f"  - Active Connections: {connections[1]}")

    cursor.execute("SELECT table_schema 'Database', SUM(data_length + index_length) / 1024 / 1024 'Size in MB' FROM information_schema.TABLES WHERE table_schema = 'droidsecanalytica' GROUP BY table_schema;")
    db_size = cursor.fetchone()
    if db_size:
        print(f"  - Database Size: {db_size[1]:.2f} MB")

def format_seconds_to_dhms(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"
