import os
import subprocess
import logging
import datetime

# Constants
LOG_FILE = 'logs/static_analysis.log'
ANALYSIS_OUTPUT_DIR = 'results'

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

        print(manifest_path)

        # Extract package name

        # Extract permissions and categorize them

        # Extract metadata for specified elements

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
    return

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

def run_static_analysis(apk_path):
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


def read_android_manifest(manifest_path):
    """
    Read the contents of the AndroidManifest.xml file.

    Args:
        manifest_path (str): Path to the AndroidManifest.xml file.

    Returns:
        list or None: List of lines from the manifest or None on failure.
    """
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            return f.readlines()
        
    except FileNotFoundError:
        logging.error(f"Error: File not found - {manifest_path}")
    except Exception as e:
        logging.error(f"Error reading AndroidManifest.xml: {e}")

    return None

def manifest_to_txt(apk):
    """
    Copy AndroidManifest.xml contents to a text file.

    Args:
        apk (str): Path to the APK file.
    """
    manifest_path = f"./{apk[:-4]}/AndroidManifest.xml"
    output_path = "Output/AndroidManifest.txt"
    
    try:
        with open(manifest_path, "r") as manifest_file:
            manifest_content = manifest_file.read()
            
        with open(output_path, "w") as output_file:
            output_file.write(manifest_content)

        print(f"AndroidManifest.xml successfully copied to {output_path}")

    except FileNotFoundError:
        logging.error(f"Error: {manifest_path} not found.")
    except IOError as err:
        logging.error(f"Error reading or writing file: {err}")

def get_manifest_permissions(android_manifest):
    """
    Extract permissions from the AndroidManifest.xml.

    Args:
        android_manifest (list): List of lines from the manifest.

    Returns:
        list: List of detected permissions.
    """
    permissions_found = []

    for line in android_manifest:
        line = line.strip()

        if "uses-permission" in line and "android:name=" in line:
            permission = line.split("android:name=\"")[1].split("\"")[0]
            permissions_found.append(permission)

        elif "android.permission." in line:
            permission = line.split("android.permission.")[1].split("\"")[0]
            permissions_found.append(permission)

    detected_permissions = sorted(set(permissions_found))
    return detected_permissions

def get_manifest_components(manifest, component_type):
    """
    Extract components (services, activities, providers) from the manifest.

    Args:
        manifest (list): List of lines from the manifest.
        component_type (str): Type of component to extract.

    Returns:
        list: List of detected components.
    """
    components = [line.split(f"android:name=\"")[1].split("\"")[0] for line in manifest if f"<{component_type} " in line]
    components.sort()
    return components

def find_manifest_attribute(manifest, attr):
    """
    Find the value of a specific attribute in the manifest.

    Args:
        manifest (list): List of lines from the manifest.
        attr (str): Attribute to search for.

    Returns:
        str or None: Value of the attribute or None if not found.
    """
    for i in manifest:
        x = i.find(attr + "=\"")
        buffer = i[x:]

        # check if at the end of the tag
        if not buffer.find("\" ") == -1:
            y = buffer.find("\" ")
        else:
            y = buffer.find("\">")

        return buffer[(buffer.find("\"") + 1) : y]

    return None

def get_manifest_features_used(manifest):
    """
    Extract features used in the manifest.

    Args:
        manifest (list): List of lines from the manifest.

    Returns:
        dict: Dictionary of features and their status (True/False).
    """
    uses_features = dict()
    unknown_features = []

    for index in manifest:
        if "<uses-feature " in index:
            feature_name = ""
            gl_es_version = ""

            if "android:name=\"" in index:
                feature_name = find_manifest_attribute([index], 'android:name')

            elif "android:glEsVersion=\"" in index:
                gl_es_version = find_manifest_attribute([index], 'android:glEsVersion')

            else:
                unknown_features.append(index.strip())
                continue

            key = feature_name if feature_name else f"glEsVersion={gl_es_version}"

            if "android:required=\"" in index:
                status = find_manifest_attribute([index], 'android:required').lower()

                if status == "true":
                    uses_features[key] = True
                    continue

            uses_features[key] = False

    if unknown_features:
        logging.warning("\nUnknown Features Found:")
        for i, feature in enumerate(unknown_features, start=1):
            logging.warning(f"[{i}] {feature}")

    return uses_features

def log_android_manifest_permissions(apk):
    """
    Log permissions from the AndroidManifest.xml to a file.

    Args:
        apk (str): Path to the APK file.
    """
    apk_name = apk[:-4]
    permissions_log = "Output/ApkPermissionLog.txt"
    android_manifest = read_android_manifest(f"./{apk_name}/AndroidManifest.xml")
    detected_permissions = get_manifest_permissions(android_manifest)

    with open(permissions_log, "w") as log:
        log.write(f"APK NAME: {apk_name}\n")
        log.write(f"Number of permissions: {len(detected_permissions)}\n\n")

        log.write("Detected permissions:\n")
        log.write("---------------------\n")
        for index, permission in enumerate(detected_permissions, start=1):
            log.write(f"[{index}] {permission}\n")

def analyze_android_manifest(apk_path):
    """
    Analyze and log information from the AndroidManifest.xml.

    Args:
        apk_path (str): Path to the APK file.
    """
    log_name = "Output/ManifestAnalysis.txt"
    log_date = datetime.datetime.now().strftime("%A %B %d, %Y %I:%M %p")
    manifest = read_android_manifest(apk_path)

    # Create log
    with open(log_name, "w") as log:
        log.write(f"Date: {log_date}\n\n")

        # Meta Data
        log.write("Meta-Data\n")
        log.write(f"Package: {find_manifest_attribute(manifest, 'package')}\n")
        log.write(f"Compiled SDK Version: {find_manifest_attribute(manifest, 'compileSdkVersion')}\n")
        log.write(f"Compiled SDK Version Codename: {find_manifest_attribute(manifest, 'compileSdkVersionCodename')}\n")
        log.write(f"Platform Build Version Code: {find_manifest_attribute(manifest, 'platformBuildVersionCode')}\n")
        log.write(f"Platform Build Version Name: {find_manifest_attribute(manifest, 'platformBuildVersionName')}\n")

        features = get_manifest_features_used(manifest)
        if features:
            log.write("\nUses-Features\n")
            for feature, value in features.items():
                log.write(f"{feature}: {value}\n")

        services = get_manifest_components(manifest, 'service')
        if services:
            log.write("\nServices\n")
            for x in services:
                log.write(f"{x}\n")

        activities = get_manifest_components(manifest, 'activity')
        if activities:
            log.write("\nActivities\n")
            for x in activities:
                log.write(f"{x}\n")

        providers = get_manifest_components(manifest, 'provider')
        if providers:
            log.write("\nProviders\n")
            for x in providers:
                log.write(f"{x}\n")