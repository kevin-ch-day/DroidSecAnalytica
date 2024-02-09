from database import DBConnectionManager as DBConn

def truncate_table():
    query = "TRUNCATE TABLE android_permissions"
    with DBConn() as db:
        db.execute_query(query, None)  # Assuming execute_query() can handle both execution and parameter passing

def insert_records(id, records):
    insert_query = """
        INSERT INTO android_permissions 
        (permission_name, constant_value, alternatively, description, note, protection_level, added_in_api, deprecated_in_api, no_longer_supported, no_third_party_apps, category, use_instead, vendor, andro_short_desc, andro_long_desc, andro_type, last_updated)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    with DBConn() as db:
        for record in records:
            db.execute_query(insert_query, record)  # Passing record as parameters for the query

def get_next_permission_id():
    query = "SELECT MAX(permission_id) AS max_id FROM android_permissions"
    with DBConn() as db:
        result = db.execute_query(query, None)  # Fetching the maximum permission_id
        if result and result[0]['max_id'] is not None:
            return result[0]['max_id'] + 1  # Return the next permission_id
        else:
            return 1  # Return 1 if no records exist

def fetch_all_permissions():
    query = "SELECT * FROM android_permissions"
    with DBConn() as db:
        results = db.execute_query(query, None)  # Fetching results without parameters
    return results

def main():
    records = fetch_all_permissions()

    truncate_table()
    insert_records(records)

    next_id = get_next_permission_id()

    permissions = fetch_all_permissions()
    for permission in permissions:
        print(permission)

if __name__ == '__main__':
    main()
