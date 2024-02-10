# permission_analyzer.py

import os
import xml.etree.ElementTree as ET
from static_analysis import apk_decompilation
from database import DBFunct_Perm, DBRecordInserts
from utils import user_prompts, logging_utils

# Handle APK permission detection process
def handle_apk_permission_detection(analysis_id, apk_path):
    decompiled_apk_path = apk_decompilation.decompile_apk(apk_path)
    permissions = extract_apk_permissions(decompiled_apk_path)
    return process_permissions(analysis_id, permissions)

# Extract permissions from the decompiled APK's manifest
def extract_apk_permissions(decompiled_apk_path):
    manifest_path = os.path.join(decompiled_apk_path, "AndroidManifest.xml")
    try:
        # Parse the manifest file
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing the manifest file: {e}")
        return []
    
    # Define namespace for Android attributes
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    # Extract permissions using the Android namespace
    return [perm.attrib[f'{{{ns["android"]}}}name'] for perm in root.findall(".//uses-permission", ns)]

# Process permissions extracted from the APK
def process_permissions(analysis_id, apk_id, permissions):
    for permission in permissions:
        try:
            # Find the permission record in the database
            perm_id = DBFunct_Perm.get_permission_id_by_name(permission)
            if perm_id:
                # Process a known standard permission
                DBFunct_Perm.check_standard_permission_record(id, permission)
                DBRecordInserts.insert_vt_permission(analysis_id, apk_id, perm_id, None)
            else:
                process_unknown_permission(analysis_id, apk_id, permission)

        except Exception as e:
            print(f"Error processing permission {permission}: {e}")

def process_unknown_permission(analysis_id, apk_id, permission_name):
    try:
        # Attempt to retrieve the record for the unknown permission by its name
        unknown_permission_record = DBFunct_Perm.get_unknown_permission_record_by_name(permission_name)

        if unknown_permission_record:
            # If the unknown permission has been previously detected
            permission_id = unknown_permission_record[0]
            print(f"Unknown Permission ID: {permission_id}")
            DBFunct_Perm.check_unknown_permission_record(permission_id, permission_name)
        else:
            # Prompt for user decision on new unknown permission
            print("\n[**] New unknown permission detected:")
            print(f"Name:\t\t{permission_name}")
            user_decision = input("Save this unknown permission? (y/n): ").strip().lower()

            if user_decision == 'y':
                # User chose to save the permission
                permission_id = DBFunct_Perm.insert_unknown_permission_record(permission_name)
                print(f"New Unknown Permission ID: {permission_id}")
                print(f"Permission '{permission_name}' saved and linked with analysis ID {analysis_id} and APK ID {apk_id}.")
            else:
                return

        # Link the permission with the analysis and APK if permission_id is defined
        if permission_id:
            if DBRecordInserts.insert_vt_permission(analysis_id, apk_id, None, permission_id):
                print(f"Permission '{permission_name}' linked with analysis ID {analysis_id} and APK ID {apk_id}.")
            else:
                print("Failed to link permission with analysis and APK.")

        user_prompts.pause_until_keypress()

    except Exception as e:
        logging_utils.log_error(f"An error occurred while processing unknown permission '{permission_name}': {e}")



