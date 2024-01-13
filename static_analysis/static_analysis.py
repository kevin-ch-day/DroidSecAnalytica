# static_analysis.py

# python libraries
import os
import sys
import subprocess
import logging
import hashlib
from typing import Optional, Dict, List

from . import virustotal_api as vt
from . import manifest_analysis

current_dir = os.path.dirname(__file__)
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
from database import database_operations as db

LOG_FILE = 'logs/static_analysis.log'
ANALYSIS_OUTPUT_DIR = 'output'
METADATA_ELEMENTS = [
    "uses-permission", "application", "activity", "service", "provider",
    "receiver", "uses-library", "uses-feature", "instrumentation", "uses-sdk",
    "meta-data", "permission"]

# Setting up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

def decompile_apk(apk_path: str, output_directory: str) -> Optional[str]:
    try:
        subprocess.run(["apktool", "d", "-f", apk_path, "-o", output_directory], check=True)
        logging.info(f"APK decompiled successfully. Output directory: {output_directory}")
        return output_directory
    except subprocess.CalledProcessError as e:
        logging.error(f"Error decompiling APK: {e}")
        return None

def analyze_android_manifest(manifest_path: str) -> Optional[Dict[str, List[Dict]]]:
    if not os.path.exists(manifest_path):
        logging.error(f"AndroidManifest.xml not found at {manifest_path}")
        return None

    try:
        manifest_content = read_file(manifest_path)
        manifest_data = {element: manifest_analysis.extract_metadata(manifest_content, element) for element in METADATA_ELEMENTS}
        logging.info("AndroidManifest.xml analysis completed.")
        return manifest_data
    except Exception as e:
        logging.error(f"Error analyzing AndroidManifest.xml: {e}")
        return None
  
def calculate_hashes(apk_file_path):
    # Check if the file is an APK file
    if not apk_file_path.lower().endswith('.apk'):
        print("The provided file is not an APK file.")
        return False

    # Initialize the dictionary to store hashes
    hashes = {"MD5": None, "SHA1": None, "SHA256": None}

    try:
        with open(apk_file_path, 'rb') as file:
            file_data = file.read()

        # Calculate and store hashes
        hashes["MD5"] = hashlib.md5(file_data).hexdigest()
        hashes["SHA1"] = hashlib.sha1(file_data).hexdigest()
        hashes["SHA256"] = hashlib.sha256(file_data).hexdigest()

        # Display the hashes
        print("\nAPK Calculated Hashes")
        print("-" * 60)
        print(f"File  : {os.path.basename(apk_file_path)}")
        for hash_type, hash_value in hashes.items():
            print(f"{hash_type:6}: {hash_value}")
        print("-" * 60)

    except FileNotFoundError:
        print(f"Error: The file '{apk_file_path}' does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return hashes

# Create apk sample record

def create_apk_record(filename, filesize, md5, sha1, sha256):
    conn = db.connect_to_database()
    if conn is None:
        print("Failed to establish a database connection.")
        return False
    
    try:
        if db.create_apk_record(conn, filename, filesize, md5, sha1, sha256):
            print("Malware sample record successfully saved.")
            return True
        else:
            print("Failed to save the malware sample record.")
            return False
        
    except Exception as e:
        print(f"An error occurred while saving the malware sample record: {e}")
        return False
    
    finally:
        db.close_database_connection(conn)

# Run static analysis
def run_static_analysis(apk_path: str):
    file_basename = os.path.basename(apk_path)
    apk_hashes = calculate_hashes(apk_path)
    file_size_bytes = os.path.getsize(apk_path)
    file_size_mb = file_size_bytes / 1024
    print(f"\nAPK file size(s):")
    print(f" {file_size_bytes:.2f} Bytes")
    print(f" {file_size_mb:.2f} MB\n")
    #input("Press any button to continue...")

    try:
        #output_directory = decompile_apk(apk_path, f"{ANALYSIS_OUTPUT_DIR}/{os.path.splitext(file_basename)[0]}")
        output_directory = False
        if output_directory:
            manifest_path = os.path.join(output_directory, "AndroidManifest.xml")
            manifest_data = analyze_android_manifest(manifest_path)
            if manifest_data:
                manifest_element = manifest_analysis.analyze_manifest_element(manifest_path)
                save_static_results(apk_path, manifest_data, manifest_element)
            
        # virustotal.com scan
        #vt.virustotal_scan(apk_path)

        # Create malware sample record
        create_apk_record(file_basename, file_size_bytes, apk_hashes["MD5"], apk_hashes["SHA1"], apk_hashes["SHA256"])

    except Exception as e:
        logging.error(f"Error during static analysis: {e}")

# save_static_results()
def save_static_results(apk_path, manifest_data, manifest_element):
    file_path = 'output/static_analysis_results.txt'
    try:
        with open(file_path, "w") as f:
            f.write(f"Static Analysis Results\n")
            f.write(f"APK: {os.path.basename(apk_path)}\n")
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

def read_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.readlines()
        
    except FileNotFoundError:
        logging.error(f"Error: File not found - {file_path}")
    except Exception as e:
        logging.error(f"Error reading file: {e}")

    return None
