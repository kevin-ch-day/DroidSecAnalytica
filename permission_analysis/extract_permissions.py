import os
import xml.etree.ElementTree as ET
from static_analysis import apk_decompilation
from utils import logging_utils

# Setup logging
logging_utils.setup_logging()

# Handle APK permission detection process
def handle_apk_permission_detection(analysis_id, apk_path):
    decompiled_apk_path = apk_decompilation.decompile_apk(apk_path)
    permissions = extract_apk_permissions(decompiled_apk_path)
    #return process_permissions(analysis_id, permissions)

# Extract permissions from the decompiled APK's manifest
def extract_apk_permissions(decompiled_apk_path):
    manifest_path = os.path.join(decompiled_apk_path, "AndroidManifest.xml")
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    permissions = []

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        permissions = [perm.attrib[f'{{{ns["android"]}}}name'] for perm in root.findall(".//uses-permission", ns)]
    except ET.ParseError as e:
        logging_utils.log_error(f"Error parsing the manifest file: {e}")
        return []
    except KeyError as e:
        logging_utils.log_error(f"Missing expected attribute in manifest: {e}")
        return []

    return permissions