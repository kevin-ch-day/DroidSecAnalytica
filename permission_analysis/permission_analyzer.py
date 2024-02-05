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

def analyze_permissions(permissions):
    permission_count = len(permissions)
    print(f"The APK has {permission_count} permissions: {permissions}")

    known_permissions = list()
    unknown_permissions = list()
    for index in permissions:

        # Check permissions
        perm_id = DBFunct_Perm.get_permission_id_by_name(index.name)
        if perm_id:
            # Detected permission is known
            known_permissions.append((perm_id, index.name))
        
        else:
            # Detected permission is unknown
            unknown_id = DBFunct_Perm.get_unknown_permission_id(index.name)
            unknown_permissions.append([unknown_id, index])
            if not unknown_id:
                process_unknown_permission(index)
    
def process_unknown_permission(permission_name):
    unknown_id = DBFunct_Perm.get_unknown_permission_id(permission_name)
    if not unknown_id:
        result = DBRecordInserts.insert_unknown_permission(permission_name)
        if not result:
            print("Failed to add permission.")

def add_permission(permission):
    result = DBRecordInserts.insert_android_permission(permission.name)
    if not result:
        print("Failed to add permission.")