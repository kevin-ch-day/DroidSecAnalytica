# permission_analysis.py

import xml.etree.ElementTree as ET
from typing import List, Dict

def extract_all_permissions(root: ET.Element) -> List[str]:
    """ Extracts all permissions used in the AndroidManifest.xml file. """
    permissions = []
    for perm in root.iter('uses-permission'):
        permissions.append(perm.get('name'))
    return permissions

def identify_overprivileged_apps(manifest_data: Dict) -> Dict:
    """Identify overprivileged apps based on the number of permissions."""
    analysis_results = {'overprivileged': False, 'overprivileged_score': 0}
    
    max_expected_permissions = 10
    actual_permissions_count = len(manifest_data.get('uses-permission', []))
    
    if actual_permissions_count > max_expected_permissions:
        excess_permissions = actual_permissions_count - max_expected_permissions
        overprivilege_score = excess_permissions * 5  # You can adjust the score multiplier as needed
        analysis_results['overprivileged'] = True
        analysis_results['overprivileged_score'] = overprivilege_score

    return analysis_results

def check_sensitive_permissions(manifest_data: Dict) -> List[str]:
    """Identify sensitive permissions used in the manifest."""
    sensitive_permissions = ['android.permission.SEND_SMS', 'android.permission.READ_CONTACTS']
    return [perm for perm in manifest_data.get('uses-permission', []) if perm in sensitive_permissions]

def check_network_permissions(manifest_data: Dict) -> List[str]:
    """Identify network-related permissions used in the manifest."""
    network_permissions = ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE']
    return [perm for perm in manifest_data.get('uses-permission', []) if perm in network_permissions]

def check_dangerous_permissions(manifest_data: Dict) -> List[str]:
    """Identify dangerous permissions used in the manifest."""
    dangerous_permissions = ['android.permission.CAMERA', 'android.permission.RECORD_AUDIO']
    return [perm for perm in manifest_data.get('uses-permission', []) if perm in dangerous_permissions]

def check_location_permissions(manifest_data: Dict) -> List[str]:
    """Identify location-related permissions used in the manifest."""
    location_permissions = ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_COARSE_LOCATION']
    return [perm for perm in manifest_data.get('uses-permission', []) if perm in location_permissions]

def check_custom_permissions(manifest_data: Dict, custom_permissions: List[str]) -> List[str]:
    """Identify custom-defined permissions used in the manifest."""
    return [perm for perm in manifest_data.get('uses-permission', []) if perm in custom_permissions]
