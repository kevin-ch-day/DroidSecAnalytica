# APKPermissionAnalyzer.py

import xml.etree.ElementTree as ET
from typing import List
from utils import logging_utils
from . import permission_auditor
from database import DBConnectionManager

# Analyze permissions in an APK file
def analyze_apk_permissions(apk_path: str, target_api_level: int = None) -> None:
    try:
        print(f"Analyzing permissions for APK: {apk_path}\n")

        manifest_data = load_and_parse_manifest(apk_path)
        permissions = extract_permissions_from_manifest(manifest_data)

        if not permissions:
            print("No permissions found in the APK.")
            return

        permission_summary = {
            'total': len(permissions),
            'risk_levels': {'low': 0, 'medium': 0, 'high': 0},
            'api_level_issues': 0,
            'categories': {}
        }

        print("Permissions found in the APK:")
        for perm in permissions:
            perm_detail = DBConnectionManager.execute_query(
                "SELECT * FROM android_permissions WHERE permission_name = %s",
                (perm,),
                fetch=True
            )
            if perm_detail:
                perm_detail = perm_detail[0]
                print(f"- {perm} (Risk: {perm_detail['risk_level']}, API Level: {perm_detail['added_in_api_level']})")
                
                # Update summary data
                permission_summary['risk_levels'][perm_detail['risk_level']] += 1
                if target_api_level and perm_detail['added_in_api_level'] > target_api_level:
                    permission_summary['api_level_issues'] += 1
                category = perm_detail['category']
                permission_summary['categories'].setdefault(category, []).append(perm)

        # Security Assessments
        overprivileged_info = permission_auditor.assess_overprivileged_status(permissions)
        sensitive_perms = permission_auditor.find_sensitive_permissions(permissions)

        # Display Summary
        print("\nSecurity Assessment Summary:")
        print(f"Total Permissions: {permission_summary['total']}")
        print(f"Risk Levels: {permission_summary['risk_levels']}")
        
        if target_api_level:
            print(f"Permissions exceeding target API level {target_api_level}: {permission_summary['api_level_issues']}")
        print(f"Sensitive Permissions: {', '.join(sensitive_perms) if sensitive_perms else 'None'}")
        print(f"Overprivileged Assessment: {overprivileged_info}")

        for category, perms in permission_summary['categories'].items():
            print(f"Category '{category}': {len(perms)} permissions")

    except Exception as e:
        logging_utils.log_error(f"Error during permissions analysis: {e}")
        print("An error occurred. Please check the logs for details.")

def extract_permissions_from_manifest(manifest_data: ET.Element) -> List[str]:
    try:
        # Namespace for Android XML
        namespace = {'android': 'http://schemas.android.com/apk/res/android'}
        nsmap = {key: f"{{{value}}}" for key, value in namespace.items()}

        # Extract permissions, avoiding duplicates
        permissions = list({perm.get(nsmap['android'] + 'name') for perm in manifest_data.iter('uses-permission')})

        return [perm for perm in permissions if perm is not None]

    except ET.ParseError as parse_err:
        # Handle XML parsing errors specifically
        logging_utils.log_error(f"XML Parsing Error in extracting permissions: {parse_err}")
    except Exception as e:
        # Handle any other exceptions
        logging_utils.log_error(f"Unexpected error in extracting permissions: {e}")

    return []

def load_and_parse_manifest(manifest_path: str) -> ET.Element:
    if not manifest_path:
        raise ValueError("No path provided for AndroidManifest.xml.")

    try:
        tree = ET.parse(manifest_path)
        return tree.getroot()

    except ET.ParseError as e:
        raise Exception(f"Failed to parse AndroidManifest.xml: {e}")

    except FileNotFoundError:
        raise FileNotFoundError(f"AndroidManifest.xml not found at path: {manifest_path}. Ensure the APK is properly decompiled.")