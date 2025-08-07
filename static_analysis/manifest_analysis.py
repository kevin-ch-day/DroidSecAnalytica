# static_analysis/manifest_analysis.py

import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from permissions_analysis import permission_categories_data as pc_data
from . import display_manifest_elements

def analyze_manifest(manifest_data: Dict):
    """Analyzes the manifest data and prints the analysis with more insights."""
    print("Manifest Analysis:\n")
    display_manifest_elements.print_permissions(manifest_data.get('uses-permission', []))
    #display_manifest_elements.print_application(manifest_data.get('application', [{}])[0])
    #display_manifest_elements.print_activities(manifest_data.get('activity', []))
    #display_manifest_elements.print_broadcast_receivers(manifest_data.get('receiver', []))
    #display_manifest_elements.print_services(manifest_data.get('service', []))
    #display_manifest_elements.print_providers(manifest_data.get('provider', []))
    #display_manifest_elements.print_intent_filters(manifest_data.get('intent-filter', []))
    #display_manifest_elements.print_data(manifest_data.get('data', []))
    #display_manifest_elements.print_meta_data(manifest_data.get('meta-data', []))
    #display_manifest_elements.print_actions(manifest_data.get('action', []))
    ##display_manifest_elements.print_categories(manifest_data.get('category', []))

    analyze_suspicious_permissions(manifest_data.get('uses-permission', []), manifest_data.get('service', []))
    categorize_permissions(manifest_data.get('uses-permission', []))
    analyze_exported_components(manifest_data)


def categorize_permissions(permissions: List[Dict]):
    """Categorize permissions based on predefined categories in permission_categories_data.py."""
    permission_groups = {
        "Overlay Permissions": pc_data.overlay_permissions,
        "SMS Permissions": pc_data.sms_permissions,
        "Processes Permissions": pc_data.processes_permissions,
        "Phone Permissions": pc_data.phone_permissions,
        "Storage Permissions": pc_data.storage_permissions,
        "Network Permissions": pc_data.network_permissions,
        "System File Permissions": pc_data.system_file_permissions,
        "Accessibility Permissions": pc_data.accessibility_permissions,
        "Package Permissions": pc_data.package_permissions,
        "Camera Permissions": pc_data.camera_permissions,
        "Video Permissions": pc_data.video_permissions,
        "User Interface Permissions": pc_data.user_interface_permissions,
        "Location Permissions": pc_data.location_permissions,
        "Booting Permissions": pc_data.booting_permissions,
        "Contact Permissions": pc_data.contact_permissions
    }

    categorized_permissions = {category: [] for category in permission_groups}
    uncategorized_permissions = []

    # Categorize the permissions
    for permission in permissions:
        permission_name = permission.get('name', 'Unknown').split('.')[-1]  # Extract the final name
        categorized = False

        for category, perm_list in permission_groups.items():
            if permission_name in perm_list:
                categorized_permissions[category].append(permission_name)
                categorized = True
                break

        if not categorized:
            uncategorized_permissions.append(permission_name)

    # Print categorized permissions
    print("\n--- Categorized Permissions ---")
    for category, perms in categorized_permissions.items():
        if perms:
            print(f"{category}:")
            for perm in perms:
                print(f"  - {perm}")

            print()

    # Print uncategorized permissions if any
    if uncategorized_permissions:
        print("\n--- Uncategorized Permissions ---")
        for perm in uncategorized_permissions:
            print(f"  - {perm}")
    print()

def analyze_suspicious_permissions(permissions: List[Dict], services: List[Dict]):
    """Analyze suspicious permissions, including those in services."""
    suspicious_permissions = set(
        pc_data.sms_permissions +
        pc_data.overlay_permissions +
        pc_data.accessibility_permissions +
        pc_data.package_permissions +
        ["DELETE_PACKAGES"]
    )

    permission_groups = {
        "SMS Permissions": pc_data.sms_permissions,
        "Overlay Permissions": pc_data.overlay_permissions,
        "Accessibility Permissions": pc_data.accessibility_permissions,
        "Package Permissions": pc_data.package_permissions,
        "Other Suspicious Permissions": ["DELETE_PACKAGES"]
    }

    found_suspicious = {perm.get('name', 'Unknown').split('.')[-1] for perm in permissions if perm.get('name', 'Unknown').split('.')[-1] in suspicious_permissions}

    for service in services:
        permission = service.get('permission', 'Unknown').split('.')[-1]
        if permission in suspicious_permissions:
            found_suspicious.add(permission)

    categorized_suspicious = {category: [] for category in permission_groups}
    uncategorized_suspicious = []

    for permission in found_suspicious:
        categorized = False
        for category, perm_list in permission_groups.items():
            if permission in perm_list:
                categorized_suspicious[category].append(permission)
                categorized = True
                break
        if not categorized:
            uncategorized_suspicious.append(permission)

    if found_suspicious:
        print("--- Suspicious Permissions ---")
        for category, perms in categorized_suspicious.items():
            if perms:
                print(f"{category}:")
                for perm in perms:
                    print(f"  - {perm}")
        if uncategorized_suspicious:
            print("Uncategorized Suspicious Permissions:")
            for perm in uncategorized_suspicious:
                print(f"  - {perm}")
    else:
        print("--- No Suspicious Permissions Found ---")
    print()


def analyze_exported_components(manifest_data: Dict):
    """Warn about exported components that lack permission protection."""
    component_types = ["activity", "service", "receiver", "provider"]
    print("--- Exported Components Without Permissions ---")
    found = False

    for comp_type in component_types:
        for component in manifest_data.get(comp_type, []):
            exported = component.get("exported", "").lower()
            permission = component.get("permission")
            if exported == "true" and not permission:
                name = component.get("name", "Unknown")
                print(f"{comp_type.capitalize()}: {name}")
                found = True

    if not found:
        print("None detected.")
    print()

def parse_manifest(manifest_path: str) -> Optional[Dict]:
    """Parse the AndroidManifest.xml file."""

    permission_buffer = list()

    if not os.path.exists(manifest_path):
        print(f"Error: AndroidManifest.xml not found at {manifest_path}")
        return None

    try:
        root = ET.parse(manifest_path).getroot()
        manifest_data = {}

        for element in root.iter():
            tag = element.tag.split("}")[-1]  # Extract tag name, ignoring XML namespace
            if tag not in manifest_data:
                manifest_data[tag] = []

            attributes = {k.split("}")[-1]: v for k, v in element.attrib.items()}  # Extract attributes

            # Check specifically for the 'android:permission' attribute in service and receiver tags
            if tag in ['service', 'receiver'] and 'permission' in attributes:
                permission = attributes['permission']
                print(f"Permission found in <{tag}>: {permission}")
                print("Permission: " + attributes['permission'] + "\n")
                attributes['permission'] = permission

                permission_buffer.append({'name': attributes['permission']})

            manifest_data[tag].append(attributes)
        
        # for i in manifest_data:
        #     if i == 'uses-permissions':
        #         for x in permission_buffer:
        #             manifest_data[i].append(x)

        return manifest_data

    except ET.ParseError as e:
        print(f"Error: XML parsing error - {e}")
        return None
