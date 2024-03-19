# static_analysis.py

import os
import subprocess
import platform
from typing import Optional

from utils import logging_utils, app_utils
from . import manifest_analysis

# Constants for file paths
ANALYSIS_OUTPUT_DIR = 'output'

def handle_apk_decompilation():
    apk_path = app_utils.android_apk_selection()
    decompile_apk(apk_path, 'output')

def decompile_apk(apk_path: str, output_directory: str) -> Optional[str]:
    # Check OS and exit if Windows
    if platform.system() == "Windows":
        logging_utils.log_error("This function cannot be executed on Windows.")
        return None

    # Check if OS is Kali Linux or Ubuntu
    if "kali" in platform.version().lower() or "ubuntu" in platform.version().lower():
        try:
            subprocess.run(["apktool", "d", "-f", apk_path, "-o", output_directory], check=True)
            logging_utils.log_info(f"APK decompiled successfully. Output directory: {output_directory}")
            return output_directory
        except subprocess.CalledProcessError as e:
            logging_utils.log_error(f"Error decompiling APK: {e}")
            return None
    else:
        logging_utils.log_error("This function can only be executed on Kali Linux or Ubuntu.")
        return None

# Run static analysis
def apk_static_analysis(apk_path: str):

    # local analysis
    file_basename = os.path.basename(apk_path)
    try:
        output_directory = decompile_apk(apk_path, f"{ANALYSIS_OUTPUT_DIR}/{os.path.splitext(file_basename)[0]}")
        if output_directory:
            manifest_path = os.path.join(output_directory, "AndroidManifest.xml")
            manifest_data = manifest_analysis.analyze_android_manifest(manifest_path)
            if manifest_data:
                #manifest_element = manifest_analysis.analyze_manifest_element(manifest_path)
                pass
                
        else:
            print("Error decompiling the APK file")
    except Exception as e:
        logging_utils.log_error(f"Error: static local analysis: {e}")

    try:
        # Virustotal.com scan
        # virustotal_analysis(apk_path)
        pass

    except Exception as e:
        logging_utils.log_error(f"Error: virustotal analysis: {e}")