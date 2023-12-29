import os
import subprocess
import logging
from xml.etree import ElementTree as ET

# Constants
LOG_FILE = 'logs/static_analysis.log'
ANALYSIS_OUTPUT_DIR = 'analysis_results'

# List of common and potentially risky permissions
COMMON_PERMISSIONS = ["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE", "WRITE_EXTERNAL_STORAGE"]
POTENTIALLY_RISKY_PERMISSIONS = ["READ_SMS", "WRITE_SMS", "SEND_SMS", "RECEIVE_SMS", "ACCESS_FINE_LOCATION"]

# Metadata elements to extract
METADATA_ELEMENTS = ["uses-permission", "application", "activity", "service", "provider"]

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_output_directory():
    """Create the output directory if it doesn't exist."""
    os.makedirs(ANALYSIS_OUTPUT_DIR, exist_ok=True)

def decompile_apk(apk_path):
    """
    Decompile an APK file and save the decompiled code.

    Args:
        apk_path (str): The path to the APK file.
    """
    try:
        output_directory = os.path.join(ANALYSIS_OUTPUT_DIR, os.path.splitext(os.path.basename(apk_path))[0])
        create_output_directory()
        subprocess.run(["apktool", "d", apk_path, "-o", output_directory], check=True)
        logging.info(f"APK decompiled successfully. Output directory: {output_directory}")
        return output_directory

    except subprocess.CalledProcessError as e:
        logging.error(f"Error decompiling APK: {e}")
        return None

def analyze_android_manifest(decompiled_dir):
    """
    Analyze the AndroidManifest.xml file in the decompiled directory.

    Args:
        decompiled_dir (str): The directory containing the decompiled APK.

    Returns:
        dict: A dictionary containing metadata from the manifest file.
    """
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    manifest_data = {}
    
    try:
        if not os.path.exists(manifest_path):
            logging.error(f"AndroidManifest.xml not found at {manifest_path}")
            return None

        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Extract package name
        package_name = root.attrib.get("package", "N/A")

        # Extract permissions and categorize them
        permissions = [node.attrib.get("name", "N/A") for node in root.findall(".//uses-permission")]
        categorized_permissions = categorize_permissions(permissions)

        # Extract metadata for specified elements
        metadata = {}
        for element in METADATA_ELEMENTS:
            metadata[element] = extract_metadata(root, element)

        manifest_data["package_name"] = package_name
        manifest_data["permissions"] = categorized_permissions
        manifest_data["metadata"] = metadata

        logging.info("AndroidManifest.xml analysis completed.")
        return manifest_data

    except Exception as e:
        logging.error(f"Error analyzing AndroidManifest.xml: {e}")
        return None

def extract_metadata(root, element_name):
    """
    Extract metadata for a specified element from the AndroidManifest.xml.

    Args:
        root (Element): The root element of the AndroidManifest.xml.
        element_name (str): The name of the element to extract metadata for.

    Returns:
        list: A list of dictionaries containing metadata for the specified element.
    """
    metadata = []
    elements = root.findall(f".//{element_name}")
    for elem in elements:
        metadata_item = {}
        metadata_item["name"] = elem.attrib.get("name", "N/A")
        # Additional metadata attributes to extract can be added here
        metadata.append(metadata_item)
    return metadata

def categorize_permissions(permissions):
    """
    Categorize permissions into common, potentially risky, and uncommon.

    Args:
        permissions (list): List of permissions requested by the app.

    Returns:
        dict: Categorized permissions.
    """
    categorized_permissions = {
        "common_permissions": [],
        "uncommon_permissions": [],
        "potentially_risky_permissions": []
    }

    for permission in permissions:
        if permission in COMMON_PERMISSIONS:
            categorized_permissions["common_permissions"].append(permission)
        elif permission in POTENTIALLY_RISKY_PERMISSIONS:
            categorized_permissions["potentially_risky_permissions"].append(permission)
        else:
            categorized_permissions["uncommon_permissions"].append(permission)

    return categorized_permissions

def execute_static_analysis(apk_path):
    """
    Main function for static analysis of an APK file.

    Args:
        apk_path (str): The path to the APK file.
    """
    print(f"Performing static analysis on {apk_path}...\n")
    
    try:
        decompiled_dir = decompile_apk(apk_path)
        if decompiled_dir:
            manifest_data = analyze_android_manifest(decompiled_dir)
            
            if manifest_data:
                # Print or save the analyzed data
                print("Static analysis completed.")
                save_results(apk_path, manifest_data)

    except Exception as e:
        print(f"Error during static analysis: {str(e)}")

def save_results(apk_path, manifest_data):
    """
    Save the static analysis results to a file.

    Args:
        apk_path (str): The path to the APK file.
        manifest_data (dict): The analyzed data from the AndroidManifest.xml file.
    """
    try:
        create_output_directory()
        output_file = os.path.join(ANALYSIS_OUTPUT_DIR, f"{os.path.splitext(os.path.basename(apk_path))[0]}_analysis_results.txt")
        
        with open(output_file, "w") as f:
            f.write("Static Analysis Results:\n")
            f.write(f"APK Name: {os.path.basename(apk_path)}\n")
            f.write(f"Package Name: {manifest_data.get('package_name', 'N/A')}\n")
            
            # Permissions
            f.write("\nPermissions:\n")
            f.write("Common Permissions: {}\n".format(", ".join(manifest_data["permissions"]["common_permissions"])))
            f.write("Potentially Risky Permissions: {}\n".format(", ".join(manifest_data["permissions"]["potentially_risky_permissions"])))
            f.write("Uncommon Permissions: {}\n".format(", ".join(manifest_data["permissions"]["uncommon_permissions"])))

            # Metadata
            f.write("\nMetadata:\n")
            for element, metadata_list in manifest_data["metadata"].items():
                f.write(f"{element}:\n")
                for index, metadata_item in enumerate(metadata_list, start=1):
                    f.write(f"[{index}] Name: {metadata_item['name']}\n")

        logging.info(f"Static analysis results saved to {output_file}")

    except Exception as e:
        logging.error(f"Error saving analysis results: {e}")

if __name__ == "__main__":
    # Example usage:
    apk_path = "path_to_your_apk.apk"
    execute_static_analysis(apk_path)
