# static_analysis.py

# python libraries
import os
import sys
import subprocess
import platform
import logging
from typing import Optional, Dict, List

from database import DBUtils
from utils import app_utils, app_display, user_prompts

from . import manifest_analysis
from . import vt_requests, vt_response_handler

current_dir = os.path.dirname(__file__)
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

LOG_FILE_PATH = 'logs/static_analysis.log'
ANALYSIS_OUTPUT_DIR = 'output'
METADATA_ELEMENTS = ["uses-permission", "application", "activity", "service",
                     "provider", "receiver", "uses-library", "uses-feature",
                     "instrumentation", "uses-sdk", "meta-data", "permission"]

# Setting up logging
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# static analysis menu
def static_analysis_menu():
    # Menu display
    print(app_display.format_menu_title("Static Analysis Menu"))
    print(app_display.format_menu_option(1, "Check if sample has been previously analyzed"))
    print(app_display.format_menu_option(2, "Decompile APK file for detailed analysis"))
    print(app_display.format_menu_option(3, "In-depth static analysis on APK"))
    print(app_display.format_menu_option(4, "In-depth static analysis on Hash"))
    print(app_display.format_menu_option(5, "Static APK Analysis II"))
    print(app_display.format_menu_option(6, "Permissions Analysis"))
    print(app_display.format_menu_option(7, "Display available APK Files"))
    print(app_display.format_menu_option(8, "Display APK File Hashes"))
    print(app_display.format_menu_option(9, "Perform VirusTotal.com APK Analysis"))
    print(app_display.format_menu_option(10, "Perform VirusTotal.com Hash IOC Analysis"))
    print(app_display.format_menu_option(0, "Return to Main Menu"))

    # Collecting user's choice
    menu_options = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '0']
    menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", menu_options)

    # Check previous analysis status
    if menu_choice == '1':
        handle_sample_check()

    # Decompile APK for analysis
    elif menu_choice == '2':
        handle_apk_decompilation()

    # In-depth analysis on APK
    elif menu_choice == '3':
        handle_indepth_apk_analysis()

    # In-depth analysis on Hash
    elif menu_choice == '4':
        handle_indepth_hash_analysis()

    # Static APK Analysis II
    elif menu_choice == '5':
        handle_static_apk_analysis_beta()

    # Analyze APK permissions
    elif menu_choice == '6':
        handle_permissions_analysis()

    # Display available APK files
    elif menu_choice == '7':
        app_utils.display_apk_files()

    # Display APK file hashes
    elif menu_choice == '8':
        display_apk_file_hashes()

    # VirusTotal analysis on APK
    elif menu_choice == '9':
        perform_virustotal_apk_analysis()

    # VirusTotal analysis on Hash IOC
    elif menu_choice == '10':
        perform_virustotal_hash_analysis()

    # Return to Main Menu
    elif menu_choice == '0':
        return

def handle_sample_check():
    print(app_display.format_menu_title("Check Previously Analyzed"))
    print(app_display.format_menu_option(1, "Enter APK Path"))
    print(app_display.format_menu_option(2, "Enter Hash IOT"))
    print(app_display.format_menu_option(3, "Return to menu"))
    print(app_display.format_menu_option(0, "Exit Application"))
    user_options = ['1', '2', '3', '0']
    user_choice = app_utils.get_user_choice("\nEnter your choice: ", user_options)

    if user_choice == 0:
        exit()

    elif user_choice == 1:
        apk_path = app_utils.prompt_user_enter_apk_path()
        # check if apk has records

    elif user_choice == 2:
        hash_ioc = app_utils.prompt_user_enter_hash_ioc()
        # check if apk has records

    elif user_choice == 3:
        return

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
                save_static_results(apk_path, manifest_data, manifest_element)
        else:
            print("Error decompiling the apk file")
        
        # Virustotal.com scan
        result = vt_requests.query_apk(apk_path)
        if result:
            vt_response_handler.parse_response(result)
        else:
            print("Error in processing the APK file request.")

    except Exception as e:
        logging.error(f"Error during static analysis: {e}")

# Run static analysis
def virustotal_analysis(apk_path: str):
    try:
        result = vt_requests.query_apk(apk_path)
        if result:
            vt_response_handler.parse_response(result)
        else:
            print("Error in processing the APK file request.")

    except Exception as e:
        logging.error(f"Error during static analysis: {e}")

# Handling permissions analysis
def handle_permissions_analysis():
    print("Performing permissions analysis...")

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

# Save the static scan results
def save_static_results(apk_basename, manifest_data, manifest_element):
    file_path = 'output/static_analysis_results.txt'
    try:
        with open(file_path, "w") as f:
            f.write(f"Static Analysis Results\n")
            f.write(f"APK: {apk_basename}\n")
            f.write("=" * 60 + "\n\n")

            write_manifest_data(f, manifest_data)
            write_manifest_element_data(f, manifest_element)

        logging.info(f"Static analysis results saved to {file_path}")

    except Exception as e:
        logging.error(f"Error saving analysis results: {e}")

def write_manifest_data(file, manifest_data):
    file.write("Manifest Data:\n")
    file.write("-" * 60 + "\n")
    for element, metadata_list in manifest_data.items():
        file.write(f"  {element.capitalize()}:\n")
        for index, metadata_item in enumerate(metadata_list, start=1):
            file.write(f"    [{index}] Name: {metadata_item['name']}\n")
        file.write("\n")

def write_manifest_element_data(file, manifest_element):
    file.write("Manifest Element Data:\n")
    file.write("-" * 60 + "\n")
    for attribute, value in manifest_element.items():
        if value:
            description = get_attribute_description(attribute)
            file.write(f"  {attribute}:\n")
            file.write(f"    Value: {value}\n")
            file.write(f"    Description: {description}\n\n")

def get_attribute_description(attribute):
    attribute_description = {
        "package": "The name of the package",
        "compileSdkVersion": "The compile SDK version",
        "compileSdkVersionCodename": "The compile SDK version codename",
        "platformBuildVersionCode": "The platform build version code",
        "platformBuildVersionName": "The platform build version name",
        "targetSdkVersion": "The target SDK version",
        "versionCode": "The version code",
        "versionName": "The version name",
        "installLocation": "The install location",
        "debuggable": "Whether the app is debuggable",
        "applicationLabel": "The application label",
        "packageInstaller": "The package installer",
    }
    return attribute_description.get(attribute, "No description available")