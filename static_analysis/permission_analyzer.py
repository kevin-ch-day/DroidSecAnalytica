# permission_analyzer.py

import os
import xml.etree.ElementTree as ET 
import apk_decompilation

def extract_permissions(decompiled_apk_path):
    manifest_path = os.path.join(decompiled_apk_path, "AndroidManifest.xml")
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    permissions = [perm.attrib[f'{{{ns["android"]}}}name'] for perm in root.findall(".//uses-permission", ns)]
    
    return permissions

def analyze_extracted_permissions(permissions):
    permission_count = len(permissions)
    print(f"The APK has {permission_count} permissions: {permissions}")

    return permission_count

def analyze_permissions(apk_path):
    decompiled_apk_path = apk_decompilation.decompile_apk(apk_path)

    permissions = extract_permissions(decompiled_apk_path)

    return analyze_extracted_permissions(permissions)

if __name__ == "__main__":
    apk_path = "path/to/your/apk/file.apk"  # Specify the path to the APK file you want to analyze
    analyze_permissions(apk_path)