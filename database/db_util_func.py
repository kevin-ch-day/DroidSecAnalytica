# db_util_func.py

from . import db_conn

def check_column_value_by_id(table, column_name, record_id):
    # Checks if a specific column for a given record ID has a value.
    sql = f"SELECT {column_name} FROM {table} WHERE id = %s;"
    params = (record_id,)

    try:
        result = db_conn.execute_query(sql, params=params, fetch=True)
        if result and result[0][0] is not None and result[0][0] != '':
            return True
        else:
            return False
    except Exception as e:
        print(f"Failed to check column value for {column_name}: {e}")
        return False

def update_column_value_by_id(table, column_name, value, record_id):
    # Updates the value of a specific column for a given record ID.
    sql = f"UPDATE {table} SET {column_name} = %s WHERE id = %s;"
    params = (value, record_id)

    try:
        db_conn.execute_query(sql, params=params, fetch=False)
        print(f"Successfully updated {column_name} for record ID {record_id}.")
    except Exception as e:
        print(f"Failed to update {column_name} for record ID {record_id}: {e}")

def check_vt_malware_size(id):
    return check_column_value_by_id("malware_samples", "sample_size", id)

def check_vt_malware_formatted_size(id):
    return check_column_value_by_id("malware_samples", "formatted_sample_size", id)

def check_vt_malware_url(id):
    return check_column_value_by_id("malware_samples", "virustotal_url", id)

def update_sample_size(id, new_value):
    update_column_value_by_id("malware_samples", "sample_size", new_value, id)

def update_formatted_size_sample(id, new_value):
    update_column_value_by_id("malware_samples", "formatted_sample_size", new_value, id)

def update_virustotal_url(id, new_value):
    update_column_value_by_id("malware_samples", "virustotal_url", new_value, id)
