import mysql.connector
import os

# Paths for schema and seeds directory
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'db_schema.sql')
SEEDS_PATH = os.path.join(os.path.dirname(__file__), 'seeds/')
DB_NAME = "droidsecanalytica_dev"

# Function to display header for each process step
def display_header(message):
    print("\n" + "="*50)
    print(f"{message.center(50)}")
    print("="*50)

# Function to display footer after a process step
def display_footer():
    print("="*50)

# Function to connect to MySQL server
def connect_to_mysql(db_config):
    display_header("CONNECTING TO MYSQL SERVER")
    try:
        conn = mysql.connector.connect(
            host=db_config[0],  # Ensure we are accessing the tuple using integer indices
            user=db_config[1],  # Index 1 for username
            password=db_config[2]  # Index 2 for password
        )
        print("[SUCCESS] Connection to MySQL server established.")
        display_footer()
        return conn
    except mysql.connector.Error as err:
        print(f"[ERROR] Failed to connect to MySQL: {err}")
        display_footer()
        return None

# Function to create the database if it doesn't exist
def create_database(cursor):
    display_header(f"CHECKING FOR DATABASE '{DB_NAME}'")
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        print(f"[SUCCESS] Database '{DB_NAME}' is ready.")
    except mysql.connector.Error as err:
        print(f"[ERROR] Error creating database '{DB_NAME}': {err}")
    display_footer()

# Function to apply the schema
def apply_schema(cursor, conn):
    display_header("APPLYING DATABASE SCHEMA")
    if os.path.exists(SCHEMA_PATH):
        try:
            with open(SCHEMA_PATH, 'r') as schema_file:
                schema_sql = schema_file.read()
                for statement in schema_sql.split(';'):
                    if statement.strip():
                        cursor.execute(statement)
                conn.commit()
            print(f"[SUCCESS] Schema applied successfully from {SCHEMA_PATH}.")
        except mysql.connector.Error as err:
            print(f"[ERROR] Error applying schema: {err}")
    else:
        print(f"[ERROR] Schema file '{SCHEMA_PATH}' not found. Please ensure the schema file is in the correct location.")
    display_footer()

# Function to apply SQL seed files
def apply_seeds(cursor, conn):
    display_header("SEEDING DATABASE DATA")
    if os.path.exists(SEEDS_PATH):
        try:
            for seed_file in os.listdir(SEEDS_PATH):
                if seed_file.endswith(".sql"):
                    seed_file_path = os.path.join(SEEDS_PATH, seed_file)
                    print(f"[INFO] Applying seed data from '{seed_file}'...")
                    with open(seed_file_path, 'r') as file:
                        sql_statements = file.read().split(';')
                        for statement in sql_statements:
                            if statement.strip():
                                cursor.execute(statement)
                        conn.commit()
                    print(f"[SUCCESS] Seed data from '{seed_file}' applied successfully.")
            print(f"[INFO] All seed data has been applied.")
        except mysql.connector.Error as err:
            print(f"[ERROR] Error applying seed data: {err}")
    else:
        print(f"[ERROR] Seed directory '{SEEDS_PATH}' not found. Please ensure the seeds directory is in the correct location.")
    display_footer()

# Function to set up the database, schema, and seed data
def setup_database(db_config):
    display_header("STARTING DATABASE SETUP")
    
    # Connect to MySQL server
    conn = connect_to_mysql(db_config)
    
    if conn:
        cursor = conn.cursor()

        # Create the database
        create_database(cursor)
        
        # Reconnect to the created database
        try:
            conn.database = DB_NAME
            print(f"[INFO] Reconnected to the database '{DB_NAME}'.")
        except mysql.connector.Error as err:
            print(f"[ERROR] Failed to reconnect to the database '{DB_NAME}': {err}")
            display_footer()
            return

        # Apply the schema
        apply_schema(cursor, conn)
        
        # Apply seed data
        apply_seeds(cursor, conn)
        
        # Close the connection
        cursor.close()
        conn.close()
        print("[INFO] Database setup is complete.")
    else:
        print("[ERROR] Could not establish connection to the MySQL server. Aborting setup.")

    display_footer()
