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
    #return process_permissions(analysis_id, permissions)

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
def save_detected_permission(analysis_id, apk_id, perm):
    try:
        # Find the permission record in the database
        perm_id = DBFunct_Perm.get_permission_id_by_name(perm.name)
        if perm_id:
            print(f"Permission ID: [{perm_id}] {perm.name}")
            #DBFunct_Perm.check_standard_permission_record(id, permission)
            DBRecordInserts.insert_vt_permission(analysis_id, apk_id, perm_id, None)
        else:
            process_unknown_permission(analysis_id, apk_id, perm)

    except Exception as e:
        print(f"Error processing permission {perm}: {e}")

def fetch_unknown_permission_record(permission_name):
    return DBFunct_Perm.get_unknown_permission_record_by_name(permission_name)

def check_permission_record(record, permission):
    print("\nVirusTotal Data:")
    print(f"Name: {permission.name}")
    print(f"Short desc: {permission.short_desc}")
    print(f"Long desc: {permission.long_desc}")
    print(f"Type: {permission.permission_type}")
    
    print("\nDatabase Record:")
    print(f"Permission ID: [{record[0]}] {permission.name}")
    print(f"Name: {record[1]}")
    print(f"Short desc: {record[6]}")
    print(f"Long desc: {record[7]}")
    print(f"Type: {record[8]}")
    user_prompts.pause_until_keypress()

def prompt_and_insert_new_permission(permission, analysis_id, apk_id):
    print("\n[**] New unknown permission detected:")
    print(f"Name:\t\t{permission.name}")
    user_decision = input("Save this unknown permission? (y/n): ").strip().lower()
    if user_decision == 'y':
        permission_id = DBFunct_Perm.insert_unknown_permission_record(permission.name)
        print(f"New Unknown Permission ID: {permission_id}")
        print(f"Permission '{permission.name}' saved and linked with analysis ID {analysis_id} and APK ID {apk_id}.")
        return permission_id
    else:
        user_prompts.pause_until_keypress()
        return None

def save_unknown_permission(analysis_id, apk_id, permission_id, permission_name):
    if not DBRecordInserts.insert_vt_permission(analysis_id, apk_id, None, permission_id):
        print(f"[!!] Failed to insert Analysis ID: {analysis_id} APK ID: {apk_id} Permission: {permission_name}")
        user_prompts.pause_until_keypress()

def process_unknown_permission(analysis_id, apk_id, perm):
    try:
        # skip
        if "android.intent.action." in perm.name:
            return
        
        record = DBFunct_Perm.get_unknown_permission_record_by_name(perm.name)
        if record:
            #check_permission_record(record, perm)
            permission_id = record[0]
        else:
            permission_id = prompt_and_insert_new_permission(perm, analysis_id, apk_id)

        if permission_id:
            save_unknown_permission(analysis_id, apk_id, permission_id, perm.name)

    except Exception as e:
        logging_utils.log_error(f"An error occurred while processing unknown permission '{perm.name}': {e}")
