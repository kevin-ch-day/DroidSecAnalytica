import os
import subprocess
import logging
import re
from . import virustotal_integration
from . import manifest_analysis

LOG_FILE = 'logs/static_analysis.log'
ANALYSIS_OUTPUT_DIR = 'output'
VIRUSTOTAL_API_KEY = ''

METADATA_ELEMENTS = ["uses-permission", "application", "activity"]
METADATA_ELEMENTS += ["service", "provider", "receiver", "uses-library"]
METADATA_ELEMENTS += ["uses-feature", "instrumentation", "uses-sdk", "meta-data", "permission"]

def decompile_apk(apk_path, output_directory):
    try:
        subprocess.run(["apktool", "d", apk_path, "-o", output_directory], check=True)
        logging.info(f"APK decompiled successfully. Output directory: {output_directory}")
        return output_directory

    except subprocess.CalledProcessError as e:
        logging.error(f"Error decompiling APK: {e}")
        return None

def analyze_android_manifest(manifest_path):
    manifest_data = {}

    try:
        if not os.path.exists(manifest_path):
            logging.error(f"AndroidManifest.xml not found at {manifest_path}")
            return None

        manifest_content = read_file(manifest_path)

        for element in METADATA_ELEMENTS:
            manifest_data[element] = manifest_analysis.extract_metadata(manifest_content, element)

        logging.info("AndroidManifest.xml analysis completed.")
        return manifest_data

    except Exception as e:
        logging.error(f"Error analyzing AndroidManifest.xml: {e}")
        return None

def run_static_analysis(apk_path):
    print(f"Performing static analysis on {apk_path}\n")
    
    try:
        # Part I.
        #output_directory = decompile_apk(apk_path, f"{ANALYSIS_OUTPUT_DIR}/{os.path.splitext(os.path.basename(apk_path))[0]}")
        output_directory = None
        if output_directory:
            manifest_path = os.path.join(output_directory, "AndroidManifest.xml")

            #manifest_data = analyze_android_manifest(manifest_path)
            #manifest_element = manifest_analysis.analyze_manifest_element(manifest_path)
            #obfuscation_data = analyze_code_obfuscation(output_directory)
            #save_static_results(apk_path, manifest_data, manifest_element, obfuscation_data)

        # Part II.
        virustotal_integration.virustotal_scan(VIRUSTOTAL_API_KEY, apk_path)

        print("\nStatic analysis completed.")        

    except Exception as e:
        print(f"Error during static analysis: {str(e)}")

def print_scan_result(scan_result):
    if scan_result:
        scan_id = scan_result.get('scan_id', '')
        md5_hash = scan_result.get('md5', '')
        sha1_hash = scan_result.get('sha1', '')
        sha256_hash = scan_result.get('sha256', '')
        scan_date = scan_result.get('scan_date', '')
        positives = scan_result.get('positives', 0)
        total = scan_result.get('total', 0)
        scan_report_url = scan_result.get('permalink', '')

        print(f"Scan ID: {scan_id}")
        print(f"MD5 Hash: {md5_hash}")
        print(f"SHA1 Hash: {sha1_hash}")
        print(f"SHA256 Hash: {sha256_hash}")
        print(f"Scan Date: {scan_date}")
        print(f"Positives/Total: {positives}/{total}")
        print(f"Scan Report URL: {scan_report_url}")

        if positives > 0:
            print("WARNING: This file has been detected as malicious by one or more antivirus engines.")
    else:
        print("No VirusTotal scan results available.")

def analyze_code_obfuscation(decompiled_dir):
    obfuscation_data = {
        "eval_calls": 0,
        "reflection_usage": 0,
        "dynamic_loading": 0,
        "string_encryption": 0,
        "class_rename": 0,
        "obfuscated_variables": 0,
        "obfuscated_control_flow": 0,
    }

    try:
        for root, _, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith(".java"):
                    with open(os.path.join(root, file), "r", encoding="utf-8") as java_file:
                        java_code = java_file.read()

                        eval_calls = len(re.findall(r'eval\((.*?)\)', java_code, re.DOTALL))
                        obfuscation_data["eval_calls"] += eval_calls

                        reflection_usage = len(re.findall(r'java\.lang\.reflect\.', java_code))
                        obfuscation_data["reflection_usage"] += reflection_usage

                        dynamic_loading = len(re.findall(r'ClassLoader\.getSystemClassLoader\(\)', java_code))
                        obfuscation_data["dynamic_loading"] += dynamic_loading

                        string_encryption = len(re.findall(r'new String\(new char\[\]{(.*?)}\)', java_code))
                        obfuscation_data["string_encryption"] += string_encryption

                        class_rename = len(re.findall(r'class [a-zA-Z]{1,2}[a-zA-Z0-9]*', java_code))
                        obfuscation_data["class_rename"] += class_rename

                        obfuscated_variables = len(re.findall(r'[a-zA-Z]{1,2}[a-zA-Z0-9]*[ ]{0,1}=[ ]{0,1}[a-zA-Z]{1,2}[a-zA-Z0-9]*\(', java_code))
                        obfuscation_data["obfuscated_variables"] += obfuscated_variables

                        obfuscated_control_flow = len(re.findall(r'if \(.*?1.*?\)', java_code))
                        obfuscation_data["obfuscated_control_flow"] += obfuscated_control_flow

    except Exception as e:
        logging.error(f"Error analyzing code obfuscation: {e}")

    return obfuscation_data

def save_static_results(apk_path, manifest_data, manifest_element, code_obfuscation_data):
    try:
        output_file = os.path.join(ANALYSIS_OUTPUT_DIR, f"{os.path.splitext(os.path.basename(apk_path))[0]}_analysis_results.txt")

        with open(output_file, "w") as f:
            f.write(f"Static Analysis Results for APK: {os.path.basename(apk_path)}\n")
            f.write("=" * 60 + "\n\n")

            write_manifest_data(f, manifest_data)
            write_manifest_element_data(f, manifest_element)
            write_code_obfuscation_data(f, code_obfuscation_data)

        logging.info(f"Static analysis results saved to {output_file}")

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

def write_code_obfuscation_data(file, code_obfuscation_data):
    metrics = [
        ("Eval Calls", "Count of eval() function calls in the code."),
        ("Reflection Usage", "Count of usages of java.lang.reflect package."),
        ("Dynamic Loading", "Count of dynamic class loading operations."),
        ("String Encryption", "Count of string encryption/obfuscation operations."),
        ("Class Rename", "Count of class renaming operations."),
        ("Obfuscated Variables", "Count of obfuscated variables usage."),
        ("Obfuscated Control Flow", "Count of obfuscated control flow structures.")
    ]

    file.write("\nCode Obfuscation Analysis:\n")
    file.write("-" * 60 + "\n")

    for metric, description in metrics:
        metric_key = metric.lower().replace(' ', '_')
        value = code_obfuscation_data.get(metric_key, 0)
        
        file.write(f"  {metric}:".ljust(30))
        file.write(f"{value}\n")
        file.write("  Description:".ljust(30))
        file.write(f"{description}\n")

def read_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.readlines()
        
    except FileNotFoundError:
        logging.error(f"Error: File not found - {file_path}")
    except Exception as e:
        logging.error(f"Error reading file: {e}")

    return None
