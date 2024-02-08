# permission_analyzer.py

import os
import xml.etree.ElementTree as ET
from static_analysis import apk_decompilation
from database import DBFunct_Perm, DBRecordInserts


def handle_apk_permission_detection(apk_path):
    decompiled_apk_path = apk_decompilation.decompile_apk(apk_path)
    permissions = extract_apk_permissions(decompiled_apk_path)
    return analyze_permissions(permissions)

def extract_apk_permissions(decompiled_apk_path):
    # Path to the AndroidManifest.xml file within the decompiled APK directory
    manifest_path = os.path.join(decompiled_apk_path, "AndroidManifest.xml")
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing the manifest file: {e}")
        return []
    
    # Namespace for Android attributes in the manifest file
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    # Extract all uses-permission elements and their android:name attributes
    permissions = [perm.attrib[f'{{{ns["android"]}}}name'] for perm in root.findall(".//uses-permission", ns)]
    
    return permissions

def process_permission(permission):
    try:
        print(permission.name)
        permission_record = DBFunct_Perm.get_permission_record_by_name(permission.name)
        if permission_record:
            process_standard_permission(permission_record, permission)
        else:
            process_unknown_permission(permission)
    except Exception as e:
        print(f"Error processing permission {permission.name}: {e}")

def process_standard_permission(permission_record, permission):
    id = permission_record[0]
    DBFunct_Perm.check_standard_permission_record(id, permission.short_desc, permission.long_desc, permission.permission_type)

def process_unknown_permission(permission):
    try:
        unknown_permission_record = DBFunct_Perm.get_unknown_permission_record_by_name(permission.name)
        if unknown_permission_record:
            id = unknown_permission_record[0]
            print(f"Unknown Permission ID: {id}")
            DBFunct_Perm.check_unknown_permission_record(id, permission.short_desc, permission.long_desc, permission.permission_type)
        else:
            print("\n[**] Permission not found in database.")
            print("Name:\t\t", permission.name)
            print("Short Desc:\t", permission.short_desc)
            print("Long Desc:\t", permission.long_desc)
            print("Type:\t\t", permission.permission_type)
            DBFunct_Perm.insert_unknown_permission_record(permission.name, permission.short_desc, permission.long_desc, permission.permission_type)
            user_prompts.pause_until_keypress()
    except Exception as e:
        print(f"An error occurred while processing unknown permission: {e}")