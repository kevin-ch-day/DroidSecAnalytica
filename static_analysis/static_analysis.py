import os
import subprocess
import platform
from typing import Optional

from utils import app_utils, user_prompts, logging_utils
from . import manifest_analysis, permission_analyzer

# Constants for file paths
ANALYSIS_OUTPUT_DIR = 'output'

def check_analyzed_by_apk_path():
    apk_path = user_prompts.user_enter_apk_path()

def check_analyzed_by_hash_ioc():
    hash_ioc = user_prompts.user_enter_hash_ioc()


# Run static analysis
def apk_static_analysis(apk_path: str):
    file_basename = os.path.basename(apk_path)
    try:
        output_directory = decompile_apk(apk_path, f"{ANALYSIS_OUTPUT_DIR}/{os.path.splitext(file_basename)[0]}")
        if output_directory:
            manifest_path = os.path.join(output_directory, "AndroidManifest.xml")
            manifest_data = manifest_analysis.analyze_android_manifest(manifest_path)
            if manifest_data:
                manifest_element = manifest_analysis.analyze_manifest_element(manifest_path)
                
        else:
            print("Error decompiling the APK file")
        
        # Virustotal.com scan
        #virustotal_analysis(apk_path)

    except Exception as e:
        logging_utils.log_error(f"Error during static analysis: {e}")