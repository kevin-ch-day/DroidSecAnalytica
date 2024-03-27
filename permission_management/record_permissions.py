from database import db_insert_records, db_permissions
from utils import logging_utils, user_prompts

# Setup logging
logging_utils.setup_logger()

# Process permissions extracted from the APK
def save_detected_permission(analysis_id, apk_id, permission_adt):
    try:
        result = db_permissions.get_permission_record_by_name(permission_adt.name)
        if result:
            perm_id = result[0]
            print(f"{permission_adt.name} [{permission_adt.permission_type}]")
            db_insert_records.insert_vt_permission(analysis_id, apk_id, perm_id, None)
        else:
            process_unknown_permission(analysis_id, apk_id, permission_adt)

    except Exception as e:
        logging_utils.log_error(f"Error processing [{permission_adt.name}]: {e}")

def process_unknown_permission(analysis_id, apk_id, perm_name):
    try:
        if "android.intent.action." in perm_name:
            return
        
        record = db_permissions.get_unknown_permission_record_by_name(perm_name.name)
        if record:
            permission_id = record[0]
        else:
            print(f"\nNew unknown permission detected: {perm_name.name}")
            permission_id = prompt_and_insert_new_permission(perm_name, analysis_id, apk_id)
            save_unknown_permission(analysis_id, apk_id, permission_id, perm_name)

    except Exception as e:
        logging_utils.log_error(f"An error occurred while processing unknown permission '{perm_name}': {e}")

def prompt_and_insert_new_permission(perm_adt, analysis_id, apk_id):
    record = db_permissions.insert_unknown_permission_record(perm_adt.name, perm_adt.short_desc, perm_adt.long_desc, perm_adt.permission_type)
    print(f"New Unknown Permission ID: {record[0]}")
    print(f"Permission '{perm_adt.name}' saved and linked with analysis ID {analysis_id} and APK ID {apk_id}.")
    return record[0]

def save_unknown_permission(analysis_id, apk_id, permission_id, permission_name):
    if not db_insert_records.insert_vt_permission(analysis_id, apk_id, None, permission_id):
        logging_utils.log_error(f"[!!] Failed to insert Analysis ID: {analysis_id} APK ID: {apk_id} Permission: {permission_name}")
        user_prompts.pause_until_keypress()
