# permission_analyzer.py

import os
import xml.etree.ElementTree as ET
from static_analysis import apk_decompilation
from database import DBFunct_Perm, DBRecordInserts
from utils import user_prompts

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
    permissions = [perm.attrib[f'{{{ns["android"]}}}name'] for perm in root.findall(".//uses-permission", ns)]
    
    return permissions

# Process permissions extracted from the APK
def process_permissions(analysis_id, permissions):
    for permission in permissions:
        try:
            # Find the permission record in the database
            record = DBFunct_Perm.get_permission_record_by_name(permission)
            if record:
                process_standard_permission(analysis_id, record, permission)
            else:
                process_unknown_permission(analysis_id, permission)

        except Exception as e:
            print(f"Error processing permission {permission}: {e}")

# Process a known standard permission
def process_standard_permission(analysis_id, permission_record, permission):
    id = permission_record[0]
    DBFunct_Perm.check_standard_permission_record(id, permission)
    DBRecordInserts.

# Process an unknown permission
def process_unknown_permission(analysis_id, permission):
    try:
        unknown_permission_record = DBFunct_Perm.get_unknown_permission_record_by_name(permission)
        if unknown_permission_record:
            record_id = unknown_permission_record[0] 
            print(f"Unknown Permission ID: {record_id}")
            DBFunct_Perm.check_unknown_permission_record(record_id, permission)
        else:
            print("\n[**] Permission not found in database.")
            print("Name:\t\t", permission)
            DBFunct_Perm.insert_unknown_permission_record(permission)
            user_prompts.pause_until_keypress()
    except Exception as e:
        print(f"An error occurred while processing unknown permission: {e}")
