# static_analysis.py

import os
import subprocess
import platform
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from utils import logging_utils, app_utils
from . import manifest_analysis

# Constants for file paths
ANALYSIS_OUTPUT_DIR = 'output'

def handle_apk_decompilation():
    """Decompile the selected APK using apktool."""
    apk_path = app_utils.android_apk_selection()
    if apk_path:
        # Ensure the function cannot be executed on Windows
        if platform.system() == "Windows":
            logging_utils.log_error("This function cannot be executed on Windows.")
            return

        decompile_apk(apk_path)


def decompile_apk(apk_path: str):
    """Decompile an APK using apktool."""
    try:
        file_name = os.path.splitext(os.path.basename(apk_path))[0]
        target_output = os.path.join(ANALYSIS_OUTPUT_DIR, file_name)
        subprocess.run(["apktool", "d", "-f", apk_path, "-o", target_output], check=True)
        logging_utils.log_info(f"APK decompiled successfully. Output directory: {target_output}")

    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error decompiling APK: {e}")
    except Exception as e:
        logging_utils.log_error(f"An unexpected error occurred: {e}")


def run_analysis(apk_path: str):
    """Run static analysis on the APK."""
    manifest_path = os.path.join(apk_path, "AndroidManifest.xml")
    manifest_data = manifest_analysis.parse_manifest(manifest_path)
    if manifest_data:
        manifest_analysis.analyze_manifest(manifest_data)
