# static_analysis.py

# Standard library imports
import os
import sys
import subprocess
import platform
import logging
from typing import Optional, Dict, List

# Local application imports
from database import DBUtils
from utils import app_utils, app_display, user_prompts
from . import manifest_analysis, vt_requests, vt_response_handler, export_analysis_results

# Set up logging
LOG_FILE_PATH = 'logs/static_analysis.log'
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

# Constants for file paths
current_dir = os.path.dirname(__file__)
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

ANALYSIS_OUTPUT_DIR = 'output'
METADATA_ELEMENTS = ["uses-permission", "application", "activity", "service",
                     "provider", "receiver", "uses-library", "uses-feature",
                     "instrumentation", "uses-sdk", "meta-data", "permission"]

# Setting up logging
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

def handle_sample_check():
    print(app_display.format_menu_title("Check Previously Analyzed"))
    print(app_display.format_menu_option(1, "Enter APK Path"))
    print(app_display.format_menu_option(2, "Enter Hash IOC"))
    print(app_display.format_menu_option(3, "Return to menu"))
    print(app_display.format_menu_option(0, "Exit Application"))
    user_options = ['1', '2', '3', '0']
    user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", user_options)

    if user_choice == 0:
        exit()

    elif user_choice == 1:
        check_analyzed_by_apk_path()

    elif user_choice == 2:
        check_analyzed_by_hash_ioc()

    elif user_choice == 3:
        return

def check_analyzed_by_apk_path():
    apk_path = user_prompts.user_enter_apk_path()
    # check if apk has records

def check_analyzed_by_hash_ioc():
    hash_ioc = user_prompts.user_enter_hash_ioc()
    # check if apk has records

# Run static analysis
def precheck_sample(apk_path: str):
    apk_hashes = app_utils.calculate_hashes(apk_path)
    print("MD5:", apk_hashes["MD5"])
    print("SHA1:", apk_hashes["SHA1"])
    print("SHA256:", apk_hashes["SHA256"])

    file_size_bytes = os.path.getsize(apk_path)
    file_size_mb = file_size_bytes / 1024
    print(f"\nAPK file size(s):")
    print(f" {file_size_bytes:.2f} Bytes")
    print(f" {file_size_mb:.2f} MB\n")

    # check to see if hash has already been analyzed
    if not DBUtils.check_for_hash_record(apk_hashes):
        # hash does not have a record in malware_hashes
        print("IOC hash does not have a record")
        file_basename = os.path.basename(apk_path)
        DBUtils.create_apk_record(file_basename, file_size_bytes, apk_hashes["MD5"], apk_hashes["SHA1"], apk_hashes["SHA256"])
        
        if not DBUtils.check_if_hash_analyzed(apk_hashes):
            # hash has not been analyzed
            print("IOC hash has not been analyzed")
            # run analysis on hash

        else:
            # hash has been analyzed
            print("IOC hash has already been analyzed")
            return # return to main

    else:
        # hash does not have a record in malware_hashes
        print("IOC hash has a record")

    input("Press any button to continue...")

def handle_apk_decompilation():
    apk_path = app_utils.android_apk_selection()
    decompile_apk(apk_path)

def decompile_apk(apk_path: str, output_directory: str) -> Optional[str]:
    # Check OS and exit if Windows
    if platform.system() == "Windows":
        logging.error("This function cannot be executed on Windows.")
        return None

    # Check if OS is Kali Linux or Ubuntu
    if "kali" in platform.version().lower() or "ubuntu" in platform.version().lower():
        try:
            subprocess.run(["apktool", "d", "-f", apk_path, "-o", output_directory], check=True)
            logging.info(f"APK decompiled successfully. Output directory: {output_directory}")
            return output_directory
        except subprocess.CalledProcessError as e:
            logging.error(f"Error decompiling APK: {e}")
            return None
    else:
        logging.error("This function can only be executed on Kali Linux or Ubuntu.")
        return None

# Run static analysis
def full_analysis_scan(apk_path: str):
    file_basename = os.path.basename(apk_path)
    try:
        output_directory = decompile_apk(apk_path, f"{ANALYSIS_OUTPUT_DIR}/{os.path.splitext(file_basename)[0]}")
        if output_directory:
            manifest_path = os.path.join(output_directory, "AndroidManifest.xml")
            manifest_data = analyze_android_manifest(manifest_path)
            if manifest_data:
                manifest_element = manifest_analysis.analyze_manifest_element(manifest_path)
                export_analysis_results.save_static_results(apk_path, manifest_data, manifest_element)
        else:
            print("Error decompiling the apk file")
        
        # Virustotal.com scan
        virustotal_analysis(apk_path)

    except Exception as e:
        logging.error(f"Error during static analysis: {e}")

# Virustotal API analysis
def virustotal_analysis(apk_path: str):
    try:
        result = vt_requests.query_apk(apk_path)
        if result:
            vt_response_handler.parse_response(result)
        else:
            print("Error in processing the APK file request.")

    except Exception as e:
        logging.error(f"Error during static analysis: {e}")

def handle_permissions_analysis():
    try:
        # Prompt the user for the APK file path
        apk_path = user_prompts.prompt_user_enter_apk_path()
        logging.info(f"Analyzing permissions for APK: {apk_path}")

        # Perform the permissions analysis (assuming a function for this exists)
        permissions = analyze_apk_permissions(apk_path)
        if permissions:
            print("Permissions found in the APK:")
            for perm in permissions:
                print(f"- {perm}")
        else:
            print("No permissions found in the APK.")

    except FileNotFoundError:
        logging.error(f"APK file not found at path: {apk_path}")
        print("Error: APK file not found. Please check the file path.")
    except Exception as e:
        logging.error(f"Error during permissions analysis: {e}")
        print("An error occurred during the analysis. Please check the logs for details.")

    finally:
        # Pause and wait for user input before returning
        user_prompts.pause_until_keypress()

def analyze_apk_permissions():
    pass

def analyze_android_manifest(manifest_path: str) -> Optional[Dict[str, List[Dict]]]:
    if not os.path.exists(manifest_path):
        logging.error(f"AndroidManifest.xml not found at {manifest_path}")
        return None
    try:
        manifest_content = app_utils.read_file(manifest_path)
        manifest_data = {element: manifest_analysis.extract_metadata(manifest_content, element) for element in METADATA_ELEMENTS}
        logging.info("AndroidManifest.xml analysis completed.")
        return manifest_data
    except Exception as e:
        logging.error(f"Error analyzing AndroidManifest.xml: {e}")
        return None