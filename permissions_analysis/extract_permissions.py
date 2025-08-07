import os
import xml.etree.ElementTree as ET
from static_analysis import static_analysis
from utils import logging_utils

logger = logging_utils.get_logger(__name__)


# Handle APK permission detection process
def handle_apk_permission_detection(analysis_id, apk_path):
    """Decompile an APK and extract its declared permissions."""
    decompiled_apk_path = static_analysis.decompile_apk(apk_path)
    if not decompiled_apk_path:
        return []
    permissions = extract_apk_permissions(decompiled_apk_path)
    return permissions


# Extract permissions from the decompiled APK's manifest
def extract_apk_permissions(decompiled_apk_path):
    manifest_path = os.path.join(decompiled_apk_path, "AndroidManifest.xml")
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    permissions = []

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        permissions = [perm.attrib[f'{{{ns["android"]}}}name'] for perm in root.findall(".//uses-permission", ns)]
    except ET.ParseError:
        logger.exception("Error parsing the manifest file")
        return []
    except KeyError:
        logger.exception("Missing expected attribute in manifest")
        return []

    return permissions
