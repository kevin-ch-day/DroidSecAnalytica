from db_operations import db_conn

def resize_vt_engine_columns():
    # Retrieve column information for VARCHAR columns
    columns_info = db_conn.execute_query("SHOW FULL COLUMNS FROM vt_scan_analysis WHERE Type LIKE 'varchar(%)';", fetch=True)
    
    for col in columns_info:
        column_name, column_type = col[0], col[1]
        # Extract the size of the VARCHAR column
        size = int(column_type.split('(')[1].split(')')[0])
        
        if size > 100:
            # Alter the column size to 100 if it's over 100
            try:
                alter_sql = f"ALTER TABLE vt_scan_analysis MODIFY COLUMN {column_name} VARCHAR(100);"
                db_conn.execute_query(alter_sql, fetch=False)
                print(f"Resized column '{column_name}' from VARCHAR({size}) to VARCHAR(100).")
            except Exception as e:
                print(f"Failed to resize column '{column_name}': {e}")

if __name__ == "__main__":
    resize_vt_engine_columns()