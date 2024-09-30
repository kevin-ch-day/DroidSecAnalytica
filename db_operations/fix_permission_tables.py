from db_operations import db_conn as DBConn

def truncate_table():
    query = "TRUNCATE TABLE android_permissions"
    with DBConn() as db:
        db.execute_query(query)

def insert_records(records):
    insert_query = """
        INSERT INTO android_permissions 
        (permission_id, permission_name, constant_value, alternatively, description, note, protection_level, added_in_api, deprecated_in_api, no_longer_supported, no_third_party_apps, category, use_instead, vendor, andro_short_desc, andro_long_desc, andro_type, last_updated)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    with DBConn() as db:
        for record in records:
            db.execute_query(insert_query, record)

def fetch_all_permissions():
    query = "SELECT * FROM android_permissions"
    with DBConn() as db:
        results = db.execute_query(query)
    return results

def main():
    # Fetch all permissions to potentially do something with them before truncating
    records = fetch_all_permissions()

    truncate_table()
    
    insert_records(records)

    permissions = fetch_all_permissions()
    for permission in permissions:
        print(permission)

if __name__ == '__main__':
    main()
