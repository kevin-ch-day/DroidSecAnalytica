import os
import subprocess
import platform
from typing import Optional

from utils import app_utils, user_prompts, logging_utils, app_display
from . import manifest_analysis, apk_decompilation
from permission_audit import save_detected_permissions
from virustotal import vt_analysis, vt_requests

# Constants for file paths
ANALYSIS_OUTPUT_DIR = 'output'

# Run static analysis
def apk_static_analysis(apk_path: str):

    # local analysis
    file_basename = os.path.basename(apk_path)
    try:
        output_directory = apk_decompilation.decompile_apk(apk_path, f"{ANALYSIS_OUTPUT_DIR}/{os.path.splitext(file_basename)[0]}")
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

def handle_sample_submission():
    menu_title = "VirusTotal.com Sample Submission:"
    menu_options = {
        1: "APK",
        2: "Hash",
        0: "Return"
    }
    
    app_display.display_menu(menu_title, menu_options)
    choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['0', '1', '2'])

    if choice == '0':
        return
    
    elif choice == '1':
        apk_path = user_prompts.user_enter_apk_path()
        vt_requests.query_apk(apk_path)
        vt_data_analysis(response)
        
    elif choice == '2':
        hash_ioc = user_prompts.user_enter_hash_ioc()
        response = vt_requests.query_hash(hash_ioc)
        vt_data_analysis(response)
    
    else:
        print("Invalid choice. Please try again.")

def vt_data_analysis(response):
    vt_analysis.user_vt_data_processing(response)