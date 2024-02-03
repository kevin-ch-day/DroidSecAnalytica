import mysql.connector
import time
from typing import List, Tuple, Any

config = {
    'user': 'root',
    'password': '',
    'host': 'localhost',
    'database': 'droidsecanalytica_dev'
}

def fetch_all_permissions() -> List[Tuple[Any, ...]]:
    print("Fetching all data from 'unknown_permissions' table...")
    start_time = time.time()
    query = "SELECT constant_value, description, note, protection_level, category, andro_short_desc, andro_long_desc, andro_type"
    query += " FROM unknown_permissions ORDER BY constant_value ASC"
    
    with mysql.connector.connect(**config) as conn:
        with conn.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchall()
    
    end_time = time.time()
    print(f"Retrieved {len(result)} records in {end_time - start_time:.2f} seconds.")
    
    # Display the first 4 records, if available
    print("Displaying the first 4 records (if available):")
    for record in result[:4]:
        print(record)
    
    return result

def truncate_table():
    print("Truncating table...")
    start_time = time.time()
    truncate_query = "TRUNCATE TABLE unknown_permissions"
    check_query = "SELECT COUNT(*) FROM unknown_permissions"
    
    with mysql.connector.connect(**config) as conn:
        with conn.cursor() as cursor:
            cursor.execute(truncate_query)
            conn.commit()
            
            # Verify the table is empty
            cursor.execute(check_query)
            count = cursor.fetchone()[0]
            if count == 0:
                print("Verification successful: Table is empty.")
            else:
                print("Verification failed: Table is not empty.")
    
    end_time = time.time()
    print(f"'unknown_permissions' table truncated in {end_time - start_time:.2f} seconds.")

def insert_permissions(sorted_records: List[Tuple[Any, ...]]):
    print("Inserting sorted records back into table...")
    start_time = time.time()
    query = """
    INSERT INTO unknown_permissions
    (constant_value, description, note, protection_level, category, andro_short_desc, andro_long_desc, andro_type, last_updated)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    with mysql.connector.connect(**config) as conn:
        with conn.cursor() as cursor:
            for index, record in enumerate(sorted_records, start=1):
                cursor.execute(query, record)
                if index % 100 == 0 or index == len(sorted_records):  # Log progress every 100 records or on the last record
                    print(f"Inserted {index}/{len(sorted_records)} records...")
            conn.commit()
    end_time = time.time()
    print(f"All records inserted in {end_time - start_time:.2f} seconds.")

def main():
    print("Starting permission records processing...\n")
    start_time = time.time()

    permissions = fetch_all_permissions()
    truncate_table()
    insert_permissions(permissions)

    end_time = time.time()
    print(f"\nPermission records processing completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
