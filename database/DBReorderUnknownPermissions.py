from . import DBConnectionManager as DB

def reorder_permissions():
    with DB.database_connection() as conn:
        cursor = conn.cursor()
        # Step 1: Temporarily increase permission_id by an offset to avoid PRIMARY key conflict
        offset = 90000  # Use an offset larger than the current max permission_id in the table
        cursor.execute("""
            UPDATE unknown_permissions
            SET permission_id = permission_id + %s
        """, (offset,))

        # Step 2: Fetch all permissions with the temporary offset, ordered by your criteria (e.g., constant_value)
        cursor.execute("""
            SELECT permission_id FROM unknown_permissions
            ORDER BY constant_value ASC
        """)
        permissions = cursor.fetchall()

        # Step 3: Reset permission_id to sequential order starting from 1
        new_id = 1
        for (temp_permission_id,) in permissions:
            cursor.execute("""
                UPDATE unknown_permissions
                SET permission_id = %s
                WHERE permission_id = %s
            """, (new_id, temp_permission_id))
            new_id += 1
        conn.commit()
        print("Unknow Permissions reordered successfully.")

if __name__ == "__main__":
    reorder_permissions()
