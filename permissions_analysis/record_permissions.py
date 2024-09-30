from db_operations import db_insert_records, db_permissions, db_permission_2
from utils import logging_utils, user_prompts

# Setup logging
logging_utils.setup_logger()

# Process permissions extracted from the APK
def save_detected_permission(analysis_id, apk_id, permission_adt):
    try:
        result = db_permissions.get_permission_record_by_name(permission_adt.name)
        # standard android permission
        if result:
            perm_id = result[0]
            print(f"\t{permission_adt.name} [{permission_adt.permission_type}]")
            db_insert_records.insert_vt_permission(analysis_id, apk_id, perm_id, None, None)
        else:
            manuf_perm_id = db_permission_2.fetch_android_manufacturer_permission_id_by_value(permission_adt.name)
            if manuf_perm_id:
                db_insert_records.insert_vt_permission(analysis_id, apk_id, None, None, manuf_perm_id)
            else:
                # android permission is unknown
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

def save_unknown_permission(analysis_id, apk_id, unknown_perm_id, perm_name):
    if not db_insert_records.insert_vt_permission(analysis_id, apk_id, None, unknown_perm_id, None):
        logging_utils.log_error(f"[!!] Failed to insert Analysis ID: {analysis_id} APK ID: {apk_id} Permission: {perm_name}")
        user_prompts.pause_until_keypress()
